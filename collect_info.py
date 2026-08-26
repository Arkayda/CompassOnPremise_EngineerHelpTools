#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Сбор информационного бандла для поддержки: состояние системы, docker, конфиги
# (с секретами в виде ***), сертификаты, mysql, логи сервисов и полный отчёт diagnose.
# Результат — tar.gz архив в /tmp, который можно отправить в поддержку.
#
# Важно: содержимое security.yaml и пароли из values в бандл НЕ попадают —
# значения ключей с password/secret/token/key заменяются на "***".

import os
import re
import tarfile
from pathlib import Path
from datetime import datetime

import docker

from common import (
    assert_root, blue, warning, success, get_hostname, create_parser,
    find_installer_dir, run_cmd, get_value, load_values, exec_in_container,
    mysql_query_raw, probe_mysql_credentials,
)

assert_root()

# ---КОНСТАНТЫ---#

# ключи с секретами: значения заменяем на "***" во всех собираемых конфигах
SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|api_?key|private)", re.IGNORECASE)

# сколько строк лога каждого сервиса кладём в бандл
DEFAULT_LOG_TAIL = 500

# ---АРГУМЕНТЫ СКРИПТА---#

parser = create_parser(
    description="Сбор информационного бандла Compass On-premise для поддержки (с редактурой секретов).",
    usage="python3 collect_info.py [-e ENVIRONMENT] [-v VALUES] [--installer-dir PATH] [--output-dir DIR] [--since PERIOD]",
    epilog="Примеры:\n"
           "  python3 collect_info.py -e production -v compass\n"
           "  python3 collect_info.py --since 72h --log-tail 2000\n"
           "\n"
           "Результат: /tmp/compass_info_<хост>_<дата>.tar.gz",
)
parser.add_argument('-e', '--environment', required=False, default="production", type=str,
                    help="Окружение (для поиска файла values)")
parser.add_argument('-v', '--values', required=False, default="compass", type=str,
                    help="Имя values-файла окружения")
parser.add_argument("--installer-dir", required=False, default=None, type=str,
                    help="Каталог установленного инсталлятора (по умолчанию ищется автоматически)")
parser.add_argument("--output-dir", required=False, default="/tmp", type=str,
                    help="Куда положить бандл (по умолчанию /tmp)")
parser.add_argument("--since", required=False, default="24h", type=str,
                    help="За какой период собирать логи (формат docker: 1h, 24h, 7d)")
parser.add_argument("--log-tail", required=False, default=DEFAULT_LOG_TAIL, type=int,
                    help="Сколько строк лога каждого сервиса класть в бандл")
parser.add_argument("--no-diagnose", required=False, action="store_true",
                    help="Не запускать diagnose.py внутри бандла")
args = parser.parse_args()

# ---ХЕЛПЕРЫ---#

# записать файл в бандл с заголовком-комментарием
def write_file(bundle_dir, relative_path, content):
    target = bundle_dir / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")


# выполнить команду и вернуть текст "команда:\nвывод" (для текстовых сборок)
def capture_cmd(cmd_args, timeout=120):
    rc, out, err = run_cmd(cmd_args, timeout=timeout)
    text = "$ %s\n" % " ".join(cmd_args)
    if out.strip():
        text += out.rstrip() + "\n"
    if err.strip():
        text += "[stderr] %s\n" % err.rstrip()
    if rc != 0:
        text += "[код %d]\n" % rc
    return text + "\n"


# рекурсивно заменить секретные значения в структуре yaml
def redact_secrets(node):
    if isinstance(node, dict):
        result = {}
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                result[key] = redact_secrets(value)
            elif SECRET_KEY_RE.search(str(key)) and value not in (None, "", 0, False, []):
                result[key] = "***"
            else:
                result[key] = value
        return result
    if isinstance(node, list):
        return [redact_secrets(item) for item in node]
    return node


# ---ОСНОВНОЙ ПОТОК---#

def main():
    import yaml

    installer_dir = find_installer_dir(args.installer_dir)
    values_dict, values_path, values_error = load_values(installer_dir, args.environment, args.values)

    bundle_name = "compass_info_%s_%s" % (
        get_hostname(),
        datetime.now().strftime("%Y%m%d_%H%M%S"),
    )
    output_root = Path(args.output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    bundle_dir = output_root / bundle_name
    bundle_dir.mkdir(parents=True, exist_ok=True)

    print(blue("Собираем информационный бандл: %s" % bundle_dir))

    # 1. система
    system_text = ""
    system_text += capture_cmd(["hostname"])
    system_text += capture_cmd(["date"])
    system_text += capture_cmd(["uname", "-a"])
    system_text += capture_cmd(["sh", "-c", "grep PRETTY_NAME /etc/os-release 2>/dev/null"])
    system_text += capture_cmd(["uptime"])
    system_text += capture_cmd(["df", "-h"])
    system_text += capture_cmd(["free", "-h"])
    system_text += capture_cmd(["cat", "/proc/loadavg"])
    write_file(bundle_dir, "system.txt", system_text)

    # 2. docker
    docker_text = ""
    docker_text += capture_cmd(["docker", "version"])
    docker_text += capture_cmd(["docker", "info"])
    docker_text += capture_cmd(["docker", "node", "ls"])
    docker_text += capture_cmd(["docker", "stack", "ls"])
    docker_text += capture_cmd(["docker", "service", "ls"])
    docker_text += capture_cmd(["docker", "system", "df"])
    docker_text += capture_cmd(["docker", "ps", "-a", "--no-trunc"])
    write_file(bundle_dir, "docker.txt", docker_text)

    # список имён сервисов (используем и для упавших задач, и для сбора логов)
    rc, out, err = run_cmd(["docker", "service", "ls", "--format", "{{.Name}}"], timeout=60)
    service_names = [line.strip() for line in out.splitlines() if line.strip()]

    # упавшие задачи сервисов
    tasks_text = ""
    for service_name in service_names:
        rc_ps, out_ps, _ = run_cmd(
            ["docker", "service", "ps", "--no-trunc", "--format",
             "{{.CurrentState}}|{{.Error}}|{{.Node}}", service_name],
            timeout=60,
        )
        for line in out_ps.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[1].strip():
                tasks_text += "%s: %s\n" % (service_name, "|".join(parts).rstrip())
    write_file(bundle_dir, "docker_failed_tasks.txt", tasks_text or "упавших задач не найдено\n")

    # 3. инсталлятор и конфиги (с секретами под ***
    installer_text = ""
    if installer_dir:
        installer_text += "installer_dir: %s\n" % installer_dir
        version_file = Path(installer_dir) / ".version"
        if version_file.exists():
            installer_text += "version: %s\n" % version_file.read_text().strip()
        installer_text += capture_cmd(["git", "-C", installer_dir, "branch", "--show-current"])
        installer_text += capture_cmd(["git", "-C", installer_dir, "log", "--oneline", "-3"])
        installer_text += capture_cmd(["ls", "-la", "%s/src/" % installer_dir])
    else:
        installer_text += "каталог инсталлятора не найден\n"
    if values_error:
        installer_text += "values: %s\n" % values_error
    else:
        root_mount_path = values_dict.get("root_mount_path", "")
        installer_text += "values: %s (секреты заменены на ***)\n" % values_path
        installer_text += "root_mount_path: %s\n" % root_mount_path

        # values окружения с отредактированными секретами
        try:
            with open(values_path, "r") as values_file:
                env_values = yaml.safe_load(values_file) or {}
            write_file(
                bundle_dir,
                "config/values_env.redacted.yaml",
                yaml.dump(redact_secrets(env_values), default_flow_style=False, allow_unicode=True),
            )
        except Exception as e:
            installer_text += "не удалось прочитать values: %s\n" % e

        # security.yaml — только факт наличия и права, содержимое не собираем
        security_path = Path(root_mount_path) / "security.yaml"
        if security_path.exists():
            mode = oct(security_path.stat().st_mode & 0o777)
            installer_text += "security.yaml: есть, права %s (содержимое в бандл не входит)\n" % mode
        else:
            installer_text += "security.yaml: не найден\n"
    write_file(bundle_dir, "installer.txt", installer_text)

    # 4. сертификаты
    certs_text = ""
    if values_dict:
        ssl_dir = Path(values_dict.get("root_mount_path", "")) / "nginx" / "ssl"
        if ssl_dir.is_dir():
            for cert_path in sorted(list(ssl_dir.glob("*.crt")) + list(ssl_dir.glob("*.pem"))):
                rc, out, err = run_cmd(
                    ["openssl", "x509", "-noout", "-enddate", "-subject", "-in", str(cert_path)],
                    timeout=15,
                )
                certs_text += "%s:\n%s\n" % (cert_path.name, out.strip() if rc == 0 else "(не сертификат)")
    write_file(bundle_dir, "certs.txt", certs_text or "сертификаты не найдены\n")

    # 5. mysql: версии, uptime, базы (без данных и паролей)
    mysql_text = ""
    try:
        client = docker.from_env(timeout=60)
        mysql_containers = [
            container for container in client.containers.list()
            if "mysql" in container.name
        ]
        for container in mysql_containers:
            mysql_text += "== %s\n" % container.name
            creds = probe_mysql_credentials(container, values_dict or {})
            if creds is None:
                mysql_text += "креды не подобраны, только healthcheck из docker inspect\n\n"
                continue
            for query, title in (
                ("SELECT VERSION()", "version"),
                ("SHOW GLOBAL STATUS LIKE 'Uptime'", "uptime"),
                ("SHOW GLOBAL STATUS LIKE 'Threads_connected'", "threads_connected"),
                ("SHOW DATABASES", "databases"),
            ):
                rc, out = mysql_query_raw(container, creds[0], creds[1], query)
                # убираем варнинг mysql про пароль в командной строке — шума много, пользы нет
                out = "\n".join(
                    line for line in out.splitlines()
                    if "Using a password on the command line" not in line
                )
                mysql_text += "%s:\n%s\n" % (title, out.strip() if rc == 0 else "(ошибка запроса)")
            mysql_text += "\n"
    except Exception as e:
        mysql_text += "не удалось получить данные mysql: %s\n" % e
    write_file(bundle_dir, "mysql.txt", mysql_text)

    # 6. логи сервисов
    logs_dir = bundle_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    for service_name in service_names:
        rc_log, out_log, _ = run_cmd(
            ["docker", "service", "logs", "--since", args.since, "--tail", str(args.log_tail), service_name],
            timeout=120,
        )
        if out_log.strip():
            # имя файла: стек_сервис.log (слэши и двоеточия в имени не нужны)
            safe_name = service_name.replace("/", "_").replace(":", "_")
            write_file(logs_dir, "%s.log" % safe_name, out_log)
    write_file(bundle_dir, "logs_note.txt",
               "логи сервисов за %s, хвост %d строк на сервис (секреты в логах не редактировались)\n" % (
                   args.since, args.log_tail))

    # 7. полный отчёт диагностики
    if not args.no_diagnose:
        diagnose_path = Path(__file__).resolve().parent / "diagnose.py"
        if diagnose_path.exists():
            diagnose_cmd = [sys.executable, str(diagnose_path), "-e", args.environment, "-v", args.values, "--no-color"]
            if args.installer_dir:
                diagnose_cmd += ["--installer-dir", args.installer_dir]
            rc_diag, out_diag, err_diag = run_cmd(diagnose_cmd, timeout=600)
            write_file(bundle_dir, "diagnose.txt", out_diag + ("\n[stderr]\n%s" % err_diag if err_diag.strip() else ""))

    # 8. архив
    archive_path = output_root / ("%s.tar.gz" % bundle_name)
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(bundle_dir, arcname=bundle_name)

    archive_size = archive_path.stat().st_size
    size_text = "%.1f МБ" % (archive_size / 1024 ** 2) if archive_size >= 1024 ** 2 else "%.0f КБ" % (archive_size / 1024)
    print(success("Готово: %s (%s)" % (archive_path, size_text)))
    print("Секреты (пароли/ключи/токены) в конфигах заменены на ***; security.yaml и логи БД в бандл не входят.")
    print(warning("В логах сервисов секреты не редактировались — проверьте бандл перед пересылкой, если это критично."))


if __name__ == "__main__":
    main()
