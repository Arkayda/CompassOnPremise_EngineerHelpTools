#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Сравнение двух информационных бандлов collect_info (например, "до" и "после"
# обновления или инцидента): версии, сервисы/реплики, образы, упавшие задачи,
# ошибки в логах, сертификаты, values (уже с редактурой секретов).
#
# Запускается на машине инженера: python 3.8+, без внешних зависимостей.

import re
import difflib
import tarfile
import tempfile
import shutil
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timezone

# ---СТАТУСЫ И ЦВЕТА---#

COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_END = "\033[0m"

# ---ПАТТЕРНЫ ОШИБОК (синхронно с analyze_bundle)---#

LOG_ERROR_PATTERNS = [
    re.compile(r"\bFATAL\b"),
    re.compile(r"\bERROR\b"),
    re.compile(r"OOMKilled|Out of memory|oom-killer|Killed process \d+"),
    re.compile(r"panic:"),
    re.compile(r"NEW EXCEPTION"),
    re.compile(r"MySQL server has gone away"),
    re.compile(r"Deadlock found", re.IGNORECASE),
    re.compile(r"Segmentation fault"),
    re.compile(r"exit(ed )?(with|status)? ?(code )?255\b"),
    re.compile(r"Connection refused", re.IGNORECASE),
    re.compile(r"\btimeout\b|\bcontext deadline exceeded\b", re.IGNORECASE),
]

# ---АРГУМЕНТЫ---#

import argparse

parser = argparse.ArgumentParser(
    description="Сравнение двух бандлов collect_info: что изменилось между сборками.",
    usage="python3 bundle_diff.py <до.tar.gz|каталог> <после.tar.gz|каталог> [--no-color]",
    epilog="Примеры:\n"
           "  python3 bundle_diff.py /tmp/compass_info_host_1.tar.gz /tmp/compass_info_host_2.tar.gz\n"
           "  python3 bundle_diff.py ./bundle_old ./bundle_new --no-color\n"
           "\n"
           "Код завершения: 0 всегда (аналитический инструмент).",
)
parser.add_argument("first", type=str, help="Бандл «до» (tar.gz или распакованный каталог)")
parser.add_argument("second", type=str, help="Бандл «после» (tar.gz или распакованный каталог)")
parser.add_argument("--no-color", required=False, action="store_true", help="Отключить цветной вывод")
args = parser.parse_args()


def color(color_code, text):
    if args.no_color:
        return text
    return "%s%s%s" % (color_code, text, COLOR_END)


# ---ВСКРЫТИЕ И ЧТЕНИЕ---#

def extract_bundle(bundle_path):
    extract_dir = Path(tempfile.mkdtemp(prefix="compass_diff_"))

    with tarfile.open(bundle_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                continue
            tar.extract(member, extract_dir)

    children = list(extract_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0], extract_dir
    return extract_dir, extract_dir


def open_bundle(path_text):
    path = Path(path_text).expanduser().resolve()
    if not path.exists():
        print("Не найден бандл: %s" % path)
        sys.exit(1)

    if path.is_file():
        return extract_bundle(path)
    return path, None


def read_text(bundle_dir, relative_path):
    path = bundle_dir / relative_path
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def command_block(text, command_substring):
    lines = text.splitlines()
    block = []
    inside = False
    for line in lines:
        if line.startswith("$ ") and command_substring in line:
            inside = True
            continue
        if inside and line.startswith("$ "):
            break
        if inside:
            block.append(line)
    return "\n".join(block)


def print_section(title):
    print("")
    print(color(COLOR_CYAN, ("── %s " % title).ljust(78, "─")))


# ---ПАРСЕРЫ СЕКЦИЙ---#

# сервисы из docker.txt: имя -> (реплики, образ)
def parse_services(bundle_dir):
    text = read_text(bundle_dir, "docker.txt")
    services = {}
    for line in command_block(text, "docker service ls").splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] == "ID":
            continue
        name = fields[1]
        replicas = fields[3] if "/" in fields[3] else ""
        image = fields[4] if len(fields) >= 5 else ""
        services[name] = (replicas, image)
    return services


# счётчики кодов завершения контейнеров из docker ps -a
def parse_exit_codes(bundle_dir):
    text = read_text(bundle_dir, "docker.txt")
    codes = Counter()
    for line in command_block(text, "docker ps -a").splitlines():
        match = re.search(r"\b(Exited|Restarting)\s*\((\d+)\)", line)
        if match:
            codes["%s(%s)" % (match.group(1), match.group(2))] += 1
    return codes


# количество упавших задач
def parse_failed_tasks(bundle_dir):
    text = read_text(bundle_dir, "docker_failed_tasks.txt")
    if not text or "не найдено" in text:
        return 0
    return len(re.findall(r"non-zero exit \(\d+\)", text))


# итоги diagnose: OK/WARN/FAIL/SKIP
def parse_diagnose_summary(bundle_dir):
    text = read_text(bundle_dir, "diagnose.txt")
    if not text:
        return None
    for line in text.splitlines():
        match = re.search(r"OK:\s*(\d+)\s+WARN:\s*(\d+)\s+FAIL:\s*(\d+)\s+SKIP:\s*(\d+)", line)
        if match:
            return tuple(int(part) for part in match.groups())
    return None


# версии инсталлятора
def parse_version(bundle_dir):
    for line in read_text(bundle_dir, "installer.txt").splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


# сертификаты: имя -> срок
def parse_certs(bundle_dir):
    certs = {}
    for match in re.finditer(r"^([\w.\-]+):\s*\nnotAfter=(.+)$",
                             read_text(bundle_dir, "certs.txt"), re.MULTILINE):
        certs[match.group(1)] = match.group(2).strip()
    return certs


# логи: сервис -> число строк с ошибками
def parse_log_errors(bundle_dir):
    logs_dir = bundle_dir / "logs"
    totals = defaultdict(int)
    if not logs_dir.is_dir():
        return totals

    for log_path in logs_dir.glob("*.log"):
        try:
            lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        count = 0
        for line in lines:
            if any(pattern.search(line) for pattern in LOG_ERROR_PATTERNS):
                count += 1
        totals[log_path.stem] = count
    return totals


# ---РАЗДЕЛЫ ОТЧЁТА---#

def diff_versions(first_dir, second_dir):
    version_before = parse_version(first_dir)
    version_after = parse_version(second_dir)
    print_section("Версия инсталлятора")
    if version_before == version_after:
        print("  не менялась: %s" % (version_before or "?"))
    else:
        print("  %s -> %s" % (color(COLOR_YELLOW, version_before or "?"),
                              color(COLOR_GREEN, version_after or "?")))


def diff_services(first_dir, second_dir):
    before = parse_services(first_dir)
    after = parse_services(second_dir)

    print_section("Сервисы и реплики")

    changed, appeared, gone = [], [], []
    for name in sorted(set(before) | set(after)):
        if name not in after:
            gone.append(name)
        elif name not in before:
            appeared.append(name)
        elif before[name][0] != after[name][0]:
            changed.append((name, before[name][0], after[name][0]))

    if changed:
        for name, replicas_before, replicas_after in changed:
            is_worse = False
            try:
                is_worse = int(replicas_after.split("/")[0]) < int(replicas_before.split("/")[0])
            except (ValueError, IndexError, AttributeError):
                pass
            arrow = color(COLOR_RED, "↓") if is_worse else color(COLOR_GREEN, "↑")
            print("  %s %-50s %s -> %s" % (arrow, name, replicas_before, replicas_after))
    if appeared:
        print("  %s появились: %s" % (color(COLOR_GREEN, "+"), ", ".join(appeared[:10])))
    if gone:
        print("  %s исчезли: %s" % (color(COLOR_RED, "-"), ", ".join(gone[:10])))
    if not (changed or appeared or gone):
        print("  состав и реплики не менялись (%d сервисов)" % len(after))


def diff_images(first_dir, second_dir):
    before = parse_services(first_dir)
    after = parse_services(second_dir)

    print_section("Образы")

    changed = [(name, before[name][1], after[name][1])
               for name in sorted(set(before) & set(after))
               if before[name][1] and before[name][1] != after[name][1]]
    if changed:
        for name, image_before, image_after in changed[:15]:
            print("  %-45s %s -> %s" % (
                name.split("_")[-1],
                image_before.rsplit(":", 1)[-1],
                color(COLOR_GREEN, image_after.rsplit(":", 1)[-1]),
            ))
        if len(changed) > 15:
            print("  ... и ещё %d" % (len(changed) - 15))
    else:
        print("  образы не менялись")


def diff_failures(first_dir, second_dir):
    print_section("Инциденты")

    tasks_before, tasks_after = parse_failed_tasks(first_dir), parse_failed_tasks(second_dir)
    print("  упавшие задачи: %d -> %s" % (
        tasks_before, color(COLOR_GREEN, str(tasks_after)) if tasks_after <= tasks_before
        else color(COLOR_RED, str(tasks_after))))

    codes_before, codes_after = parse_exit_codes(first_dir), parse_exit_codes(second_dir)
    for code in sorted(set(codes_before) | set(codes_after)):
        count_before, count_after = codes_before.get(code, 0), codes_after.get(code, 0)
        if count_before == count_after:
            continue
        trend = color(COLOR_GREEN, "↓") if count_after < count_before else color(COLOR_RED, "↑")
        print("  контейнеры %s: %d -> %d %s" % (code, count_before, count_after, trend))

    if tasks_before == tasks_after and codes_before == codes_after:
        print("  без изменений")


def diff_logs(first_dir, second_dir):
    before = parse_log_errors(first_dir)
    after = parse_log_errors(second_dir)

    print_section("Ошибки в логах (по паттернам)")

    deltas = []
    for service_name in sorted(set(before) | set(after)):
        count_before, count_after = before.get(service_name, 0), after.get(service_name, 0)
        if count_before != count_after:
            deltas.append((count_after - count_before, service_name, count_before, count_after))

    deltas.sort()
    if not deltas:
        print("  количество ошибок не менялось")
        return

    for delta, service_name, count_before, count_after in deltas[:10]:
        trend = color(COLOR_GREEN, "-%d" % abs(delta)) if delta < 0 else color(COLOR_RED, "+%d" % delta)
        print("  %s %-50s %d -> %d" % (trend, service_name.split("_", 1)[-1], count_before, count_after))
    if len(deltas) > 10:
        print("  ... и ещё %d сервисов с изменениями" % (len(deltas) - 10))


def diff_values(first_dir, second_dir):
    print_section("values (редактированный конфиг)")

    text_before = read_text(first_dir, "config/values_env.redacted.yaml")
    text_after = read_text(second_dir, "config/values_env.redacted.yaml")

    if not text_before and not text_after:
        print("  values нет ни в одном бандле")
        return

    diff_lines = list(difflib.unified_diff(
        text_before.splitlines(), text_after.splitlines(),
        fromfile="до", tofile="после", lineterm="", n=1,
    ))[2:]  # пропускаем заголовки ---/+++

    if not diff_lines:
        print("  идентичны")
        return

    for line in diff_lines[:30]:
        if line.startswith("+"):
            print("  %s" % color(COLOR_GREEN, line))
        elif line.startswith("-"):
            print("  %s" % color(COLOR_RED, line))
        else:
            print("  %s" % line)
    if len(diff_lines) > 30:
        print("  ... и ещё %d строк" % (len(diff_lines) - 30))


def diff_certs(first_dir, second_dir):
    before = parse_certs(first_dir)
    after = parse_certs(second_dir)

    print_section("Сертификаты")

    changed, new = [], []
    for name in sorted(set(before) | set(after)):
        if name not in before:
            new.append(name)
        elif before[name] != after.get(name):
            changed.append((name, before[name], after.get(name, "?")))

    for name, date_before, date_after in changed:
        print("  %-25s %s -> %s" % (name, date_before, color(COLOR_GREEN, date_after)))
    if new:
        print("  %s новые: %s" % (color(COLOR_GREEN, "+"), ", ".join(new[:10])))
    if not (changed or new):
        print("  не менялись (%d серт.)" % len(after))


def diff_diagnose(first_dir, second_dir):
    summary_before = parse_diagnose_summary(first_dir)
    summary_after = parse_diagnose_summary(second_dir)

    print_section("Итоги diagnose")

    if summary_before is None and summary_after is None:
        print("  diagnose.txt нет ни в одном бандле")
        return

    if summary_before:
        print("  до:    OK=%d WARN=%d %s SKIP=%d" % (
            summary_before[0], summary_before[1],
            color(COLOR_RED, "FAIL=%d" % summary_before[2]) if summary_before[2] else "FAIL=0",
            summary_before[3]))
    else:
        print("  до:    diagnose.txt нет")
    if summary_after:
        print("  после: OK=%d WARN=%d %s SKIP=%d" % (
            summary_after[0], summary_after[1],
            color(COLOR_RED, "FAIL=%d" % summary_after[2]) if summary_after[2] else "FAIL=0",
            summary_after[3]))
    else:
        print("  после: diagnose.txt нет")


# ---ТОЧКА ВХОДА---#

def main():
    first_dir, first_root = open_bundle(args.first)
    second_dir, second_root = open_bundle(args.second)

    try:
        print("")
        print(color(COLOR_CYAN, "Сравнение бандлов"))
        print("  до:    %s" % Path(args.first).name)
        print("  после: %s" % Path(args.second).name)

        diff_versions(first_dir, second_dir)
        diff_services(first_dir, second_dir)
        diff_images(first_dir, second_dir)
        diff_failures(first_dir, second_dir)
        diff_logs(first_dir, second_dir)
        diff_values(first_dir, second_dir)
        diff_certs(first_dir, second_dir)
        diff_diagnose(first_dir, second_dir)
        print("")
    finally:
        for root in (first_root, second_root):
            if root:
                shutil.rmtree(root, ignore_errors=True)

    sys.exit(0)


if __name__ == "__main__":
    main()
