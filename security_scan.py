#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Быстрый аудит безопасности окружения Compass On-premise (read-only):
#   - пароли по умолчанию из шаблонов в values окружения
#   - плейсхолдеры (example.com, пустые секреты)
#   - опубликованные наружу порты vs ожидаемые из values (mysql наружу = FAIL)
#   - полнота SSL-цепочки главного nginx
#   - права security.yaml
#   - кто монтирует docker.sock
#
# Часть набора инструментов tools/ — работает отдельно от репозитория инсталлятора.

import re
import ssl
import socket
import subprocess
from pathlib import Path

from common import (
    assert_root, blue, warning, error, success, cyan, create_parser, run_cmd,
    find_installer_dir, load_values, get_value,
)

assert_root()

# ---КОНСТАНТЫ---#

# известные пароли-плейсхолдеры из базового src/values.yaml инсталлятора
DEFAULT_PASSWORDS = {
    "4321", "root2", "1234", "12345678", "2toor",
    "backup_user_password", "backup_archive_password",
    "rnb5zrNf", "abcdef1234567890",
}

# ключи values, в которых ждём пароль/секрет (для обхода; вложенные пути собираем сами)
PASSWORD_KEY_MARKERS = ("password", "pass", "secret", "api_secret")

# ---АРГУМЕНТЫ СКРИПТА---#

parser = create_parser(
    description="Аудит безопасности окружения Compass On-premise: пароли по умолчанию, порты, SSL, права.",
    usage="python3 security_scan.py [-e ENVIRONMENT] [-v VALUES] [--installer-dir PATH] [--no-color]",
    epilog="Примеры:\n"
           "  python3 security_scan.py -e production -v compass\n"
           "\n"
           "Код завершения: 0 — критичных проблем нет, 1 — есть FAIL.",
)
parser.add_argument('-e', '--environment', required=False, default="production", type=str,
                    help="Окружение (для поиска values-файла)")
parser.add_argument('-v', '--values', required=False, default="compass", type=str,
                    help="Имя values-файла окружения")
parser.add_argument("--installer-dir", required=False, default=None, type=str,
                    help="Каталог установленного инсталлятора (по умолчанию ищется автоматически)")
args = parser.parse_args()

# ---СОСТОЯНИЕ---#

FINDINGS = []


def add_finding(status, title, details=""):
    FINDINGS.append({"status": status, "title": title, "details": details})


# ---ПРОВЕРКА: ДЕФОЛТНЫЕ ПАРОЛИ И ПЛЕЙСХОЛДЕРЫ---#

# рекурсивно обойти values и найти пароль-подобные ключи со значениями из шаблона
def check_default_passwords(values, env_values):
    findings = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                key_lower = str(key).lower()
                child_path = "%s.%s" % (path, key) if path else str(key)
                if isinstance(value, str) and any(marker in key_lower for marker in PASSWORD_KEY_MARKERS):
                    if value in DEFAULT_PASSWORDS:
                        findings.append((child_path, value))
                else:
                    walk(value, child_path)
        elif isinstance(node, list):
            for item in node:
                walk(item, path)

    walk(env_values or {}, "")
    # и критичные пути из смёрженного конфига (могут прийти из базового файла)
    for critical_path in (
            "projects.pivot.service.mysql.root_password",
            "projects.monolith.service.mysql.root_password",
            "projects.kafka.service.kafka.password",
    ):
        value = get_value(values, critical_path)
        if value in DEFAULT_PASSWORDS:
            entry = (critical_path, value)
            if entry not in findings:
                findings.append(entry)

    if findings:
        details = "\n".join("      %s = %s" % (path, value) for path, value in findings[:10])
        add_finding("FAIL", "Пароли по умолчанию из шаблона (%d)" % len(findings),
                    details + "\n      смените в файле окружения values и перерендерьте конфиги")
    else:
        add_finding("OK", "Пароли по умолчанию", "явных паролей-плейсхолдеров в values не найдено")


def check_placeholders(values):
    problems = []

    host = get_value(values, "host")
    if host in (None, "", "example.com"):
        problems.append("host=%r (плейсхолдер)" % host)

    jitsi_app_secret = get_value(values, "projects.jitsi.jwt.app_secret")
    if not jitsi_app_secret:
        problems.append("projects.jitsi.jwt.app_secret пуст — конференции без подписи JWT")

    auth_secret = get_value(values, "projects.auth.service.go_auth.secret_key_b64")
    if auth_secret == "":
        problems.append("projects.auth...secret_key_b64 пуст — go-auth работает без ключа")

    if problems:
        add_finding("WARN", "Плейсхолдеры в конфигурации (%d)" % len(problems),
                    "\n".join("      %s" % problem for problem in problems))
    else:
        add_finding("OK", "Плейсхолдеры", "не найдены")


# ---ПРОВЕРКА: ОПУБЛИКОВАННЫЕ ПОРТЫ---#

# порты, которые опубликованы наружу, но не ожидаются из values — подозрительны
def expected_published_ports(values):
    expected = set()

    def add(port):
        try:
            if port:
                expected.add(int(port))
        except (TypeError, ValueError):
            pass

    add(get_value(values, "projects.monolith.service.nginx.external_https_port"))
    add(get_value(values, "projects.monolith.service.nginx.external_http_port"))
    add(get_value(values, "projects.auth.service.go_auth.external_grpc_port"))
    add(get_value(values, "projects.join_web.service.join_web.external_port"))
    add(get_value(values, "projects.jitsi_web.service.jitsi_web.external_port"))
    if get_value(values, "projects.outlook_add_in.is_enabled"):
        add(get_value(values, "projects.outlook_add_in.service.external_port"))
    if get_value(values, "siem.enabled_driver") == "kafka":
        add(get_value(values, "projects.kafka.service.kafka.external_port"))
        add(get_value(values, "siem.driver_data.listen_port"))

    gateway_id = get_value(values, "api_gateway_id", "gateway-1")
    add(get_value(values, "projects.api_gateway.%s.service.go_api_gateway.external_https_port" % gateway_id))

    # jitsi: веб, jicofo и просоди (включая версии компонент v0/v1/v2)
    add(get_value(values, "projects.jitsi.service.web.https_port"))
    add(get_value(values, "projects.jitsi.service.web.http_port"))
    add(get_value(values, "projects.jitsi.service.jicofo.port"))
    add(get_value(values, "projects.jitsi.service.prosody.serve_port"))
    for suffix in ("", ".v0", ".v1", ".v2"):
        add(get_value(values, "projects.jitsi.service.prosody%s.serve_port" % suffix))

    for domino_config in (get_value(values, "projects.domino") or {}).values():
        if not isinstance(domino_config, dict):
            continue
        add(domino_config.get("service", {}).get("manticore", {}).get("external_port"))
        add(domino_config.get("go_database_controller_port"))
        add(domino_config.get("go_database_controller_profiler_port"))

    jvb = get_value(values, "projects.jitsi.service.jvb.media_port")
    add(jvb)

    return expected


# опасные порты: базы и админка не должны торчать наружу
DANGEROUS_PUBLISH_PORTS = {3306: "MySQL", 9306: "Manticore", 9200: "Elasticsearch",
                           6379: "Redis", 5672: "RabbitMQ", 15672: "RabbitMQ UI",
                           27017: "MongoDB", 2375: "Docker API (без TLS!)", 2376: "Docker API"}


def check_published_ports(values):
    rc, out, err = run_cmd(["docker", "service", "ls", "--format", "{{.Name}}|{{.Ports}}"], timeout=60)
    if rc != 0:
        add_finding("WARN", "Опубликованные порты", "docker service ls не выполнился: %s" % err.strip())
        return

    expected = expected_published_ports(values)
    dangerous, unexpected = [], []

    for line in out.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        name, ports_field = line.split("|", 1)
        for match in re.finditer(r"(?:[\d.]+|\*):(\d+)->", ports_field):
            published_port = int(match.group(1))
            if published_port in DANGEROUS_PUBLISH_PORTS:
                dangerous.append("%d (%s) — сервис %s" % (
                    published_port, DANGEROUS_PUBLISH_PORTS[published_port], name))
            elif published_port not in expected:
                unexpected.append("%d — сервис %s" % (published_port, name))

    if dangerous:
        add_finding("FAIL", "Наружу опубликованы порты баз/админок (%d)" % len(dangerous),
                    "\n".join("      %s" % item for item in dangerous[:10]) +
                    "\n      закройте публикацию в compose проекта")
    elif unexpected:
        add_finding("WARN", "Неожиданные опубликованные порты (%d)" % len(unexpected),
                    "\n".join("      %s" % item for item in unexpected[:10]) +
                    "\n      сверьте со списком ожидаемых портов из values")
    else:
        add_finding("OK", "Опубликованные порты", "наружу смотрят только ожидаемые порты (%d)" % len(expected))


# ---ПРОВЕРКА: SSL-ЦЕПОЧКА---#

# получить PEM первого сертификата и количество сертификатов в цепочке от сервера
def fetch_tls_chain(host, port):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                protocol = tls_sock.version() or "?"
                der_cert = tls_sock.getpeercert(binary_form=True)
    except Exception as e:
        return None, None, str(e)

    if not der_cert:
        return None, protocol, "сервер не отдал сертификат"

    pem_first = ssl.DER_cert_to_PEM_cert(der_cert)
    return pem_first, protocol, None


def openssl_field(pem, field):
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-%s" % field],
            input=pem.encode(), capture_output=True, timeout=15,
        )
        return proc.stdout.decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def check_ssl_chain(values):
    host = get_value(values, "host")
    port = int(get_value(values, "projects.monolith.service.nginx.external_https_port") or 443)
    if not host or host == "example.com":
        add_finding("WARN", "SSL-цепочка", "host в values не задан (%r) — проверять нечего" % host)
        return

    pem, protocol, error_text = fetch_tls_chain(host, port)
    if error_text:
        # fallback: снаружи недоступен — пробуем локально с SNI
        pem, protocol, local_error = fetch_tls_chain_with_host_header(host, port)
        if local_error:
            add_finding("WARN", "SSL-цепочка",
                        "не удалось подключиться к %s:%d: %s (проверка пропущена)" % (host, port, error_text))
            return

    subject = openssl_field(pem, "subject")
    issuer = openssl_field(pem, "issuer")

    subject_cn = re.search(r"CN\s*=\s*([^,/]+)", subject)
    issuer_cn = re.search(r"CN\s*=\s*([^,/]+)", issuer)
    subject_name = subject_cn.group(1).strip() if subject_cn else "?"
    issuer_name = issuer_cn.group(1).strip() if issuer_cn else "?"

    is_self_signed = subject_name == issuer_name

    if is_self_signed:
        add_finding("WARN", "SSL-цепочка",
                    "%s:%d — сертификат self-signed (CN=%s); клиенты должны доверять корневому CA\n"
                    "      проверка цепочки неприменима; TLS %s" % (host, port, subject_name, protocol))
        return

    # не self-signed, но в handshake отдаётся только листовой сертификат?
    # с CERT_NONE python отдаёт только peer-сертификат; полноту цепочки проверяем openssl s_client
    proc = subprocess.run(
        ["openssl", "s_client", "-connect", "%s:%d" % (host, port), "-servername", host, "-showcerts"],
        input=b"", capture_output=True, timeout=15,
    )
    chain_text = proc.stdout.decode("utf-8", "ignore")
    chain_length = chain_text.count("BEGIN CERTIFICATE")

    verify_ok = ": ok" in chain_text
    verify_error = re.search(r"verify error:([^\n]+)", chain_text)

    if chain_length >= 2 and verify_ok:
        add_finding("OK", "SSL-цепочка",
                    "%s:%d — цепочка из %d сертификатов, verify ok (TLS %s)" % (host, port, chain_length, protocol))
    elif verify_error:
        add_finding("FAIL", "SSL-цепочка",
                    "%s:%d — %s; цепочка: %d серт.\n"
                    "      соберите fullchain (листовой + промежуточные) и переустановите сертификат" % (
                        host, port, verify_error.group(1).strip(), chain_length))
    elif chain_length < 2:
        add_finding("WARN", "SSL-цепочка",
                    "%s:%d — сервер отдал только листовой сертификат (CN=%s, issuer=%s)\n"
                    "      часть клиентов (Android, библиотеки) не соберут цепочку — проверьте fullchain" % (
                        host, port, subject_name, issuer_name))
    else:
        add_finding("WARN", "SSL-цепочка", "%s:%d — цепочка из %d серт., verify не ok; смотрите openssl s_client" % (
            host, port, chain_length))


def fetch_tls_chain_with_host_header(host, port):
    # повторное подключение к тому же host (для симметрии кода); локальный фолбэк не нужен,
    # т.к. fetch_tls_chain уже возвращает ошибку соединения
    return fetch_tls_chain(host, port)


# ---ПРОВЕРКА: ПРАВА И DOCKER.SOCK---#

def check_security_yaml_perms(values):
    root_mount_path = get_value(values, "root_mount_path")
    if not root_mount_path:
        add_finding("WARN", "security.yaml", "root_mount_path неизвестен")
        return

    security_path = Path(root_mount_path) / "security.yaml"
    if not security_path.exists():
        add_finding("WARN", "security.yaml", "не найден %s — окружение было развернуто?" % security_path)
        return

    mode = security_path.stat().st_mode & 0o777
    if mode & 0o077:
        add_finding("WARN", "security.yaml",
                    "права %s: файл с ключами читают все локальные пользователи — chmod 600" % oct(mode))
    else:
        add_finding("OK", "security.yaml", "права %s" % oct(mode))


def check_docker_socket_mounts():
    # легитимные сервисы, которым нужен доступ к docker-сокету
    legitimate = ("go-database-controller",)

    # docker ps --format {{.Mounts}} показывает только имена томов, bind-маунты там нет —
    # поэтому сразу inspect по всем контейнерам
    rc, out, _ = run_cmd(["docker", "ps", "-q"], timeout=60)
    if rc != 0:
        add_finding("WARN", "docker.sock", "не удалось получить список контейнеров")
        return

    mounted_containers = []
    for container_id in out.splitlines():
        container_id = container_id.strip()
        if not container_id:
            continue
        rc_inspect, inspect_out, _ = run_cmd(
            ["docker", "inspect", "--format", "{{.Name}}", container_id], timeout=30)
        if rc_inspect != 0:
            continue

        container_name = inspect_out.strip()
        rc_mounts, mounts_out, _ = run_cmd(
            ["docker", "inspect", "--format", "{{range .Mounts}}{{.Source}}\n{{end}}", container_id], timeout=30)
        if rc_mounts == 0 and "docker.sock" in mounts_out:
            mounted_containers.append(container_name)

    if not mounted_containers:
        add_finding("OK", "docker.sock", "не смонтирован ни в один контейнер")
        return

    suspicious = [name for name in mounted_containers if not any(prefix in name for prefix in legitimate)]
    if suspicious:
        add_finding("WARN", "docker.sock смонтирован в контейнеры (%d)" % len(mounted_containers),
                    "\n".join("      %s" % name for name in suspicious[:10]) +
                    "\n      доступ к сокету = root на хосте; убедитесь, что это осознанно")
    else:
        add_finding("OK", "docker.sock", "смонтирован только в ожидаемые сервисы (%d)" % len(mounted_containers))


# ---ОТЧЁТ---#

def print_report():
    order = {"FAIL": 0, "WARN": 1, "OK": 2}
    counts = {"FAIL": 0, "WARN": 0, "OK": 0}

    print("")
    print(blue("Аудит безопасности Compass On-premise"))
    print("")

    for finding in sorted(FINDINGS, key=lambda item: order[item["status"]]):
        counts[finding["status"]] += 1
        label = {"FAIL": error("[FAIL]"), "WARN": warning("[WARN]"), "OK": success("[ OK ]")}[finding["status"]]
        print("  %s %s" % (label, finding["title"]))
        if finding["details"]:
            for detail_line in finding["details"].splitlines():
                stripped = detail_line.strip()
                if stripped:
                    print("        %s" % stripped)

    print("")
    print(blue(("── Итог ").ljust(78, "─")))
    print("  %s   %s   %s" % (
        error("FAIL: %d" % counts["FAIL"]),
        warning("WARN: %d" % counts["WARN"]),
        success("OK: %d" % counts["OK"]),
    ))
    return counts


# ---ТОЧКА ВХОДА---#

def main():
    installer_dir = find_installer_dir(args.installer_dir)
    if not installer_dir:
        print(error("Каталог инсталлятора не найден (укажите --installer-dir)"))
        sys.exit(2)

    values, env_values_path, values_error = load_values(installer_dir, args.environment, args.values)
    if values_error:
        print(error("values не загружены: %s" % values_error))
        sys.exit(2)

    # сырой файл окружения (без мерджа с базовым) — для поиска дефолтов, которые пользователь не сменил
    env_values = {}
    try:
        import yaml

        env_values = yaml.safe_load(Path(env_values_path).read_text(encoding="utf-8")) or {}
    except Exception:
        pass

    print("  values: %s" % env_values_path)

    check_default_passwords(values, env_values)
    check_placeholders(values)
    check_published_ports(values)
    check_ssl_chain(values)
    check_security_yaml_perms(values)
    check_docker_socket_mounts()

    counts = print_report()
    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
