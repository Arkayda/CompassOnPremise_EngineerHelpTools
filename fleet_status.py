#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Сводный статус всех стендов: читает stands.yaml, по SSH запускает diagnose.py
# на каждом стенде (json-режим) и печатает таблицу + список проблем.
#
# Запускается на машине инженера. Требования:
#   - ssh-доступ к стендам (ключи без пароля или загруженный агент)
#   - инструменты (diagnose.py, common.py, errors_kb.yaml) разложены на стендах
#     в один каталог (см. поле tools_dir; обновляйте через scp)
#   - pyyaml локально (pip3 install pyyaml)

import json
import os
import subprocess
import argparse
from datetime import datetime

DEFAULT_TOOLS_DIR = "/tmp/tools"
DEFAULT_SSH_PORT = 22
DEFAULT_TIMEOUT = 300

parser = argparse.ArgumentParser(
    description="Сводный статус стендов Compass On-premise: diagnose по SSH из stands.yaml.",
    usage="python3 fleet_status.py [--stands FILE] [--stand NAME] [--timeout SEC]",
    epilog="Примеры:\n"
           "  cp stands.example.yaml stands.yaml  # впишите свои стенды\n"
           "  python3 fleet_status.py\n"
           "  python3 fleet_status.py --stand onpremise-test\n"
           "\n"
           "Код завершения: 0 — на всех стендах FAIL=0, 1 — есть FAIL или недоступные стенды.",
)
parser.add_argument("--stands", required=False, default="stands.yaml", type=str,
                    help="Файл со списком стендов (по умолчанию stands.yaml)")
parser.add_argument("--stand", required=False, default="", type=str,
                    help="Проверить только один стенд по имени")
parser.add_argument("--timeout", required=False, default=DEFAULT_TIMEOUT, type=int,
                    help="Таймаут SSH-сессии на стенд, секунд")
args = parser.parse_args()


# ---ЦВЕТА---#

def red(text):
    return "\033[91m%s\033[0m" % text


def yellow(text):
    return "\033[93m%s\033[0m" % text


def green(text):
    return "\033[92m%s\033[0m" % text


def cyan(text):
    return "\033[96m%s\033[0m" % text


# ---ЗАГРУЗКА КОНФИГА---#

def load_stands(path):
    try:
        import yaml
    except ImportError:
        print(red("pyyaml не установлен: pip3 install pyyaml"))
        sys.exit(2)

    try:
        config = yaml.safe_load(open(path, encoding="utf-8").read()) or {}
    except FileNotFoundError:
        print(red("Не найден %s — скопируйте stands.example.yaml и впишите свои стенды" % path))
        sys.exit(2)
    except Exception as e:
        print(red("Не удалось прочитать %s: %s" % (path, e)))
        sys.exit(2)

    stands = config.get("stands") or []
    if not isinstance(stands, list) or not stands:
        print(red("В %s нет списка stands (смотрите формат в stands.example.yaml)" % path))
        sys.exit(2)

    for stand in stands:
        if not stand.get("name") or not stand.get("host"):
            print(red("Каждый стенд требует полей name и host: %r" % stand))
            sys.exit(2)

    return stands


# ---SSH-ВЫЗОВ DIAGNOSE---#

# собрать ssh-команду для стенда
def build_ssh_command(stand):
    ssh_parts = ["ssh", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]

    if stand.get("ssh_key"):
        ssh_parts += ["-i", os.path.expanduser(str(stand["ssh_key"]))]
    if stand.get("port"):
        ssh_parts += ["-p", str(stand["port"])]

    remote_user = stand.get("user") or "root"
    ssh_parts.append("%s@%s" % (remote_user, stand["host"]))

    tools_dir = stand.get("tools_dir") or DEFAULT_TOOLS_DIR
    remote_cmd = "python3 %s/diagnose.py --json --no-color -e %s -v %s" % (
        tools_dir, stand.get("environment") or "production", stand.get("values") or "compass")
    if stand.get("installer_dir"):
        remote_cmd += " --installer-dir %s" % stand["installer_dir"]

    if stand.get("use_sudo", remote_user != "root"):
        remote_cmd = "sudo %s" % remote_cmd

    ssh_parts.append(remote_cmd)
    return ssh_parts


# достать json-отчёт diagnose из вывода ssh (могут быть sudo-баннеры)
def extract_json(output_text):
    brace_index = output_text.find("{")
    if brace_index < 0:
        return None
    try:
        return json.loads(output_text[brace_index:])
    except ValueError:
        # пробуем до последней закрывающей скобки
        brace_index_end = output_text.rfind("}")
        if brace_index_end > brace_index:
            try:
                return json.loads(output_text[brace_index:brace_index_end + 1])
            except ValueError:
                return None
    return None


def probe_stand(stand):
    started = datetime.now()
    result = {
        "name": stand["name"],
        "host": stand["host"],
        "ok": None, "warn": 0, "fail": 0, "skip": 0,
        "problems": [], "error": None,
        "seconds": 0,
    }

    try:
        proc = subprocess.run(
            build_ssh_command(stand),
            capture_output=True,
            timeout=stand.get("timeout") or args.timeout,
        )
        output = proc.stdout.decode("utf-8", "ignore") + proc.stderr.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        result["error"] = "таймаут %s сек" % (stand.get("timeout") or args.timeout)
        result["seconds"] = (datetime.now() - started).total_seconds()
        return result
    except FileNotFoundError:
        result["error"] = "ssh не найден"
        return result

    result["seconds"] = (datetime.now() - started).total_seconds()

    report = extract_json(output)
    if report is None:
        first_line = next((line for line in output.splitlines() if line.strip()), "")
        result["error"] = "диагностика не вернула json: %s" % first_line[:120]
        return result

    summary = report.get("summary") or {}
    result["ok"] = summary.get("ok", 0)
    result["warn"] = summary.get("warn", 0)
    result["fail"] = summary.get("fail", 0)
    result["skip"] = summary.get("skip", 0)

    for check_result in report.get("results") or []:
        if check_result.get("status") in ("FAIL", "WARN"):
            message = (check_result.get("message") or "").splitlines()
            result["problems"].append("[%s] %s%s" % (
                check_result["status"], check_result.get("name"),
                (": %s" % message[0][:100]) if message and message[0] else "",
            ))

    return result


# ---ОТЧЁТ---#

def print_results(results):
    print("")
    print(cyan("Статус стендов Compass On-premise"))
    print("")

    # выравнивание колонок по самому длинному имени
    name_width = max([len(result["name"]) for result in results] + [12])
    host_width = max([len(result["host"]) for result in results] + [10])

    header = "  %-*s %-*s %-18s %s" % (name_width, "стенд", host_width, "хост", "диагностика", "проблемы")
    print(header)
    print("  " + "-" * (len(header) - 2))

    for result in results:
        if result["error"]:
            status = red("НЕДОСТУПЕН")
            problems = red(result["error"])
        else:
            status = "%s %s %s %s" % (
                green("OK:%d" % result["ok"]),
                yellow("WARN:%d" % result["warn"]),
                red("FAIL:%d" % result["fail"]) if result["fail"] else "FAIL:0",
                "SKIP:%d" % result["skip"],
            )
            problems = "%d (%.0f сек)" % (len(result["problems"]), result["seconds"])
        print("  %-*s %-*s %-18s %s" % (name_width, result["name"], host_width, result["host"], status, problems))

    # детали проблем
    for result in results:
        if result["problems"]:
            print("")
            print("  %s (%s):" % (result["name"], result["host"]))
            for problem in result["problems"][:10]:
                marker_color = red if problem.startswith("[FAIL]") else yellow
                print("    %s" % marker_color(problem))
            if len(result["problems"]) > 10:
                print("    ... и ещё %d" % (len(result["problems"]) - 10))

    print("")


# ---ТОЧКА ВХОДА---#

def main():
    stands = load_stands(args.stands)
    if args.stand:
        stands = [stand for stand in stands if stand["name"] == args.stand]
        if not stands:
            print(red("Стенд %r не найден в %s" % (args.stand, args.stands)))
            sys.exit(2)

    results = []
    for stand in stands:
        print("Проверяем %s (%s)..." % (stand["name"], stand["host"]), file=sys.stderr)
        results.append(probe_stand(stand))

    print_results(results)

    has_fail = any(result["error"] or result["fail"] for result in results)
    sys.exit(1 if has_fail else 0)


if __name__ == "__main__":
    main()
