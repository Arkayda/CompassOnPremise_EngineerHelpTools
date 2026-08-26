#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Общие хелперы для инструментов диагностики (tools/).
# Намеренно не зависят от script/utils инсталлятора: папку tools/ можно скопировать
# на любой сервер как есть и запускать отдельно от репозитория.

import os
import socket
import argparse
from pathlib import Path


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# проверить, что запустили из под рута
def assert_root():
    if os.geteuid() != 0:
        die("Скрипт необходимо запускать от рута", 66)


# вывести предупреждение
def warning(text: str) -> str:
    return bcolors.WARNING + text + bcolors.ENDC


# вывести успешное сообщение
def success(text: str) -> str:
    return bcolors.OKGREEN + text + bcolors.ENDC


# вывести информационное сообщение
def blue(text: str) -> str:
    return bcolors.OKBLUE + text + bcolors.ENDC


# вывести информационное сообщение
def cyan(text: str) -> str:
    return bcolors.OKCYAN + text + bcolors.ENDC


# вывести текст с ошибкой
def error(text: str) -> str:
    return bcolors.FAIL + text + bcolors.ENDC


# вывести ошибку и завершить выполнение
def die(text: str, exit_code: int = 1):
    print(bcolors.FAIL + text + bcolors.ENDC)
    sys.exit(exit_code)


# рекурсивно влить словарь b в a (на месте), как scriptutils.merge
def merge(a: dict, b: dict, path=[]):
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif a[key] != b[key]:
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a


# имя хоста
def get_hostname() -> str:
    return socket.gethostname()


# парсер аргументов в стиле остальных скриптов репозитория
def create_parser(description: str = None, add_help: bool = True, usage: str = None,
                  epilog: str = None) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        add_help=add_help,
        description=description,
        usage=usage,
        epilog=epilog,
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog,
            max_help_position=100,
            width=600
        )
    )


# типичный каталог установленного инсталлятора
DEFAULT_INSTALLER_DIR = "/opt/onpremise-installer"


# найти каталог инсталлятора (где лежит src/values.yaml):
# 1) явный путь; 2) родитель папки tools/ (репозиторий); 3) текущая директория и выше; 4) дефолт
def find_installer_dir(explicit_path: str = None):
    if explicit_path:
        candidate = Path(explicit_path).resolve()
        if (candidate / "src" / "values.yaml").exists():
            return str(candidate)
        return None

    script_parent = Path(__file__).resolve().parent.parent
    candidates = [script_parent]

    current = Path.cwd().resolve()
    candidates.append(current)
    candidates.extend(current.parents)

    candidates.append(Path(DEFAULT_INSTALLER_DIR))

    for candidate in candidates:
        if (candidate / "src" / "values.yaml").exists():
            return str(candidate)

    return None


# выполнить команду на хосте, вернуть (код, stdout, stderr)
def run_cmd(cmd_args, timeout=60, input_bytes=None):
    import subprocess

    try:
        proc = subprocess.run(
            cmd_args,
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "ignore"), proc.stderr.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "таймаут выполнения команды: %s" % " ".join(cmd_args[:3])
    except FileNotFoundError as e:
        return 127, "", str(e)


# --- загрузка values (общая для инструментов)---#

import yaml


# загрузить values инсталлятора: базовый src/values.yaml + файл окружения
# возвращает (словарь или None, путь_файла_окружения_или_None, текст_ошибки_или_None)
def load_values(installer_dir, environment, values_name):
    import yaml as yaml_module

    if not installer_dir:
        return None, None, "каталог инсталлятора не найден (укажите --installer-dir)"

    base_values_path = Path(installer_dir) / "src" / "values.yaml"
    if not base_values_path.exists():
        return None, None, "не найден %s — это каталог установленного инсталлятора?" % base_values_path

    try:
        with base_values_path.open("r") as values_file:
            values_dict = yaml_module.safe_load(values_file) or {}
    except Exception as e:
        return None, None, "не удалось прочитать src/values.yaml: %s" % e

    env_values_path = None
    for candidate in (
            Path(installer_dir) / ("src/values.%s.%s.yaml" % (environment, values_name)),
            Path(installer_dir) / ("src/values.%s.yaml" % values_name),
    ):
        if candidate.exists():
            env_values_path = candidate
            break

    if env_values_path is None:
        return None, None, "не найден файл окружения (values.%s.%s.yaml или values.%s.yaml) в %s/src/" % (
            environment, values_name, values_name, installer_dir)

    try:
        with env_values_path.open("r") as values_file:
            env_values = yaml_module.safe_load(values_file) or {}
        merge(values_dict, env_values)
    except Exception as e:
        return None, None, "не удалось прочитать %s: %s" % (env_values_path, e)

    return values_dict, env_values_path, None


# значение из values по пути вида "projects.monolith.label"
def get_value(values_dict, path, default=None):
    node = values_dict or {}
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


# --- доступ к mysql внутри контейнеров (env -> Docker Secrets -> values)---#

# выполнить команду внутри контейнера, вернуть (код, stdout)
def exec_in_container(container, shell_cmd, timeout=60):
    try:
        result = container.exec_run(["sh", "-c", shell_cmd])
        output = result.output
        if isinstance(output, tuple):
            output = b"".join([part or b"" for part in output])
        if isinstance(output, bytes):
            output = output.decode("utf-8", "ignore")
        return result.exit_code, output or ""
    except Exception as e:
        return 126, str(e)


# выполнить mysql-запрос в контейнере; пароль передаётся через base64, чтобы не сломать шелл
def mysql_query_raw(container, user, password, sql):
    import base64
    import shlex

    password_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
    shell_cmd = (
        'DIAG_PW=$(printf %%s "%s" | base64 -d 2>/dev/null); '
        "mysql --connect-timeout=10 -h localhost -u %s -p\"$DIAG_PW\" -e %s 2>&1"
    ) % (password_b64, shlex.quote(user), shlex.quote(sql))
    return exec_in_container(container, shell_cmd, timeout=60)


# подобрать рабочие креды для mysql-контейнера: env -> Docker Secrets -> values
# возвращает (user, password) или None
def probe_mysql_credentials(container, values_dict, extra_passwords=None):
    import shlex

    password_candidates = []

    # пароли из env контейнера
    for env_item in container.attrs.get("Config", {}).get("Env", []) or []:
        for env_name in ("MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD"):
            if env_item.startswith(env_name + "="):
                value = env_item.split("=", 1)[1]
                if value and value not in password_candidates:
                    password_candidates.append(value)

    # пароли из Docker Secrets (ветка ISRepair): внутри контейнера /run/secrets/<имя>
    secrets = container.attrs.get("Config", {}).get("Secrets", {}) or {}
    secret_items = secrets.values() if isinstance(secrets, dict) else secrets
    for secret_meta in secret_items:
        secret_path = (secret_meta or {}).get("File", {}).get("Name")
        if not secret_path:
            continue
        rc, out = exec_in_container(container, "cat %s 2>/dev/null" % shlex.quote(secret_path))
        value = out.strip()
        if rc == 0 and value and value not in password_candidates:
            password_candidates.append(value)

    # пароли из values (company-mysql на разных ветках: company_mysql_pass / company_mysql_password)
    domino_id = get_value(values_dict, "domino_id", "d1")
    for values_path in (
            "projects.pivot.service.mysql.root_password",
            "projects.monolith.service.mysql.root_password",
            "projects.domino.%s.company_mysql_pass" % domino_id,
            "projects.domino.%s.company_mysql_password" % domino_id,
    ):
        value = get_value(values_dict, values_path)
        if value and value not in password_candidates:
            password_candidates.append(value)

    for value in (extra_passwords or []):
        if value and value not in password_candidates:
            password_candidates.append(value)

    user_candidates = ["root"]
    company_user = get_value(values_dict, "projects.domino.%s.company_mysql_user" % domino_id)
    if company_user and company_user not in user_candidates:
        user_candidates.append(company_user)

    for user in user_candidates:
        for password in password_candidates:
            rc, out = mysql_query_raw(container, user, password, "SELECT 1")
            if rc == 0:
                return user, password

    return None
