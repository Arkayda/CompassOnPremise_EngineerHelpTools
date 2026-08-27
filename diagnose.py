#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Диагностика работающего окружения Compass On-premise.
# Скрипт прогоняет независимые проверки (конфигурация, инфраструктура, сервисы swarm,
# HTTP-доступность, безопасность, базы, kafka, логи, бэкапы) и не останавливается на исключениях:
# любая упавшая проверка помечается как FAIL, остальные продолжают выполняться.
#
# Часть набора инструментов tools/ — работает отдельно от репозитория инсталлятора.
# Креды для mysql резолвятся по цепочке: env контейнера -> Docker Secrets -> values
# (работает и на классической схеме, и на ветке с паролями в Docker Secrets).

import os
import re
import ssl
import json
import base64
import socket
import shlex
import traceback
import email.utils
from datetime import datetime, timezone
from pathlib import Path

import docker
import requests

from common import (
    assert_root, blue, cyan, error, success, warning, die, get_hostname,
    create_parser, find_installer_dir, run_cmd, exec_in_container,
    mysql_query_raw, get_value, load_errors_kb, match_error_kb,
    probe_mysql_credentials as probe_mysql_credentials_common,
    load_values as load_values_common,
)

assert_root()

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ---КОНСТАНТЫ---#

# статусы проверок
STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"

# пороги для диска (проценты свободного места)
DISK_FREE_WARN_PERCENT = 20
DISK_FREE_FAIL_PERCENT = 10

# пороги для срока действия сертификатов (дней)
CERT_WARN_DAYS = 30
CERT_FAIL_DAYS = 7

# пороги для количества ошибок в логах сервиса за период
LOG_FAIL_COUNT = 20

# пороги для количества рестартов контейнера (за всё время жизни)
RESTART_WARN_COUNT = 5
RESTART_FAIL_COUNT = 20

# порог неподобранного backlog очереди rabbitmq (сообщений)
RABBIT_QUEUE_BACKLOG_WARN = 10000

# пороги для свежести бэкапов (часов)
BACKUP_WARN_HOURS = 48
BACKUP_FAIL_HOURS = 24 * 7

# через сколько секунд таймаут для HTTP-запросов
DEFAULT_HTTP_TIMEOUT = 15

# сколько строк лога сервиса просматриваем за период
LOG_TAIL_LIMIT = 2000

# паттерны ошибок, которые ищем в логах сервисов
LOG_ERROR_PATTERNS = [
    ("FATAL", re.compile(r"\bFATAL\b")),
    ("ERROR", re.compile(r"\bERROR\b")),
    ("OOM", re.compile(r"OOMKilled|Out of memory|oom-killer|Killed process \d+")),
    ("panic", re.compile(r"panic:")),
    ("NEW EXCEPTION", re.compile(r"NEW EXCEPTION")),
    ("MySQL server has gone away", re.compile(r"MySQL server has gone away")),
    ("deadlock", re.compile(r"Deadlock found", re.IGNORECASE)),
    ("Segmentation fault", re.compile(r"Segmentation fault")),
    ("exit 255", re.compile(r"exit(ed )?(with|status)? ?(code )?255\b")),
    ("connection refused", re.compile(r"Connection refused", re.IGNORECASE)),
    ("timeout", re.compile(r"\btimeout\b|\bcontext deadline exceeded\b", re.IGNORECASE)),
]

# сколько примеров строк на сервис показываем в группе logs
LOG_SAMPLES_PER_SERVICE = 2

# ---КОНСТАНТЫ: БЕЗОПАСНОСТЬ---#

# известные пароли-плейсхолдеры из базового src/values.yaml инсталлятора
DEFAULT_PASSWORDS = {
    "4321", "root2", "1234", "12345678", "2toor",
    "backup_user_password", "backup_archive_password",
    "rnb5zrNf", "abcdef1234567890",
}

# ключи values, в которых ждём пароль/секрет
PASSWORD_KEY_MARKERS = ("password", "pass", "secret", "api_secret")

# опасные порты: базы и админка не должны торчать наружу
DANGEROUS_PUBLISH_PORTS = {3306: "MySQL", 9306: "Manticore", 9200: "Elasticsearch",
                           6379: "Redis", 5672: "RabbitMQ", 15672: "RabbitMQ UI",
                           27017: "MongoDB", 2375: "Docker API (без TLS!)", 2376: "Docker API"}

# легитимные сервисы, которым нужен доступ к docker-сокету
DOCKER_SOCK_LEGITIMATE = ("go-database-controller",)

# порядок и заголовки групп проверок
GROUPS = [
    ("config", "Конфигурация (сверка с values)"),
    ("infra", "Инфраструктура"),
    ("requirements", "Требования к серверу"),
    ("services", "Сервисы swarm"),
    ("http", "HTTP-доступность"),
    ("security", "Безопасность"),
    ("external", "Внешние зависимости"),
    ("functional", "Функциональные смоук-тесты"),
    ("db", "Базы данных и поиск"),
    ("kafka", "Kafka (SIEM)"),
    ("logs", "Ошибки в логах"),
    ("backups", "Бэкапы"),
]

# run-once сервисы (restart_policy: none) — для них 0/1 это норма
RUN_ONCE_SERVICE_PREFIXES = ("default-file",)

# ---АРГУМЕНТЫ СКРИПТА---#

parser = create_parser(
    description="Диагностика установленного окружения Compass On-premise: конфигурация, инфраструктура, сервисы, HTTP, безопасность, базы, логи, бэкапы.",
    usage="python3 diagnose.py [-e ENVIRONMENT] [-v VALUES] [--installer-dir PATH] [--only GROUPS] [--since PERIOD] [--json] [--no-color]",
    epilog="Примеры:\n"
           "  python3 diagnose.py -e production -v compass\n"
           "  python3 diagnose.py -e production --only services,db,logs --since 24h\n"
           "  python3 diagnose.py --json > /tmp/diagnose.json\n"
           "\n"
           "Группы проверок: " + ", ".join([group[0] for group in GROUPS]) + ".\n"
           "Запускаются все группы сразу; --only сужает список.\n"
           "Код завершения: 0 — критических проблем нет, 1 — есть FAIL.",
)
parser.add_argument('-e', '--environment', required=False, default="production", type=str,
                    help="Окружение (используется для поиска файла values.<окружение>.<values>.yaml)")
parser.add_argument('-v', '--values', required=False, default="compass", type=str,
                    help="Имя values-файла окружения")
parser.add_argument("--installer-dir", required=False, default=None, type=str,
                    help="Каталог установленного инсталлятора (по умолчанию ищется автоматически)")
parser.add_argument("--only", required=False, default="", type=str,
                    help="Запустить только выбранные группы проверок (через запятую)")
parser.add_argument("--since", required=False, default="24h", type=str,
                    help="За какой период смотреть логи и упавшие задачи (формат docker: 1h, 30m, 24h; по умолчанию 24h)")
parser.add_argument("--http-timeout", required=False, default=DEFAULT_HTTP_TIMEOUT, type=int,
                    help="Таймаут HTTP-проверок в секундах")
parser.add_argument("--log-tail", required=False, default=LOG_TAIL_LIMIT, type=int,
                    help="Сколько строк лога сервиса просматривать")
parser.add_argument("--json", required=False, action="store_true",
                    help="Вывести отчёт в формате JSON (для мониторинга)")
parser.add_argument("--no-color", required=False, action="store_true",
                    help="Отключить цветной вывод")
args = parser.parse_args()

# ---ХЕЛПЕРЫ---#

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


# вывести строку с учётом флага --no-color
def print_line(text):
    if args.no_color:
        text = ANSI_ESCAPE_RE.sub("", text)
    print(text)


# статус в цвете
def status_label(status):
    colors = {
        STATUS_OK: success,
        STATUS_WARN: warning,
        STATUS_FAIL: error,
        STATUS_SKIP: cyan,
    }
    return colors[status]("[ %-4s ]" % status)


# выполнить docker-команду и распарсить вывод как список json-объектов
def docker_cli_json(cmd_args, timeout=120):
    rc, out, err = run_cmd(["docker"] + cmd_args + ["--format", "{{json .}}"], timeout=timeout)
    if rc != 0:
        raise RuntimeError("docker %s: %s" % (" ".join(cmd_args[:3]), err.strip() or out.strip()))

    items = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except ValueError:
            continue
    return items


# возраст задачи из CurrentState вида "Running 3 minutes ago" / "Shutdown about an hour ago"
# возвращает возраст в секундах или None, если не удалось разобрать
def parse_current_state_age(state_text):
    match = re.search(r"(\d+)\s+(second|minute|hour|day)s?\s+ago", state_text or "")
    if not match:
        # "about a minute ago" и прочие варианты без числа считаем ~1 минутой
        if re.search(r"ago\s*$", state_text or ""):
            return 60
        return None
    multipliers = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    return int(match.group(1)) * multipliers[match.group(2)]


# период вида "1h"/"30m"/"24h" в секундах (для фильтрации задач по возрасту)
def parse_since_period(text):
    match = re.fullmatch(r"(\d+)([smhd])", (text or "").strip())
    if not match:
        return 3600
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return int(match.group(1)) * multipliers[match.group(2)]


# ---РЕЕСТР ПРОВЕРОК---#

CHECKS = []


# декоратор регистрации проверки: функция получает контекст и пишет результаты через ctx.record()
def check(group, name):
    def decorator(func):
        CHECKS.append({"group": group, "name": name, "func": func})
        return func

    return decorator


# ---КОНТЕКСТ ДИАГНОСТИКИ---#

class DiagnoseContext:
    def __init__(self):
        self.results = []
        self.started_at = datetime.now()

        # каталог инсталлятора: явный путь, репозиторий (родитель tools/), cwd и выше, /opt/onpremise-installer
        self.installer_dir = find_installer_dir(args.installer_dir) or ""
        self.environment = args.environment
        self.values_name = args.values
        self.stack_prefix = "%s-%s" % (self.environment, self.values_name)
        self.values = {}
        self.values_loaded = False
        self.values_file_path = None
        self.values_error = None

        self.docker_client = None
        self.docker_error = None

        # кэш: список стеков из docker stack ls
        self._stacks = None
        # кэш: сервисы по стекам {stack: [service_json, ...]}
        self._stack_services = {}
        # кэш: контейнеры по стекам {stack: [container, ...]}
        self._stack_containers = {}
        # кэш: подобранные креды mysql {container_id: (user, password)}
        self._mysql_creds = {}

    # записать результат проверки
    def record(self, group, name, status, message=""):
        self.results.append({
            "group": group,
            "name": name,
            "status": status,
            "message": str(message),
        })

    # подключение к docker (один раз)
    def docker(self):
        if self.docker_client is None and self.docker_error is None:
            try:
                self.docker_client = docker.from_env(timeout=60)
            except Exception as e:
                self.docker_error = str(e)
        return self.docker_client

    # список имён стеков
    def stacks(self):
        if self._stacks is None:
            if self.values_loaded:
                # сверяемся с конфигом: интересуют только стеки нашего префикса
                self._stacks = [
                    item["Name"] for item in docker_cli_json(["stack", "ls"])
                    if item.get("Name", "").startswith(self.stack_prefix + "-") or item.get("Name") == self.stack_prefix
                ]
            else:
                # values не найден — смотрим вообще все стеки
                self._stacks = [item["Name"] for item in docker_cli_json(["stack", "ls"])]
        return self._stacks

    # сервисы стека (docker stack services)
    def stack_services(self, stack):
        if stack not in self._stack_services:
            self._stack_services[stack] = docker_cli_json(["stack", "services", stack])
        return self._stack_services[stack]

    # контейнеры стека (по лейблу swarm)
    def stack_containers(self, stack):
        if stack not in self._stack_containers:
            client = self.docker()
            if client is None:
                self._stack_containers[stack] = []
            else:
                try:
                    self._stack_containers[stack] = client.containers.list(
                        all=True,
                        filters={"label": "com.docker.stack.namespace=%s" % stack},
                    )
                except Exception:
                    self._stack_containers[stack] = []
        return self._stack_containers[stack]

    # значение из values по пути вида "projects.monolith.label"
    def value(self, path, default=None):
        node = self.values
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


# ---РАЗРЕШЕНИЕ КРЕДОВ MYSQL---#

# подобрать рабочие креды для mysql-контейнера (env -> Docker Secrets -> values), с кэшем на прогон
def probe_mysql_credentials(ctx, container):
    container_id = container.id
    if container_id in ctx._mysql_creds:
        return ctx._mysql_creds[container_id]

    found = probe_mysql_credentials_common(container, ctx.values)
    ctx._mysql_creds[container_id] = found
    return found


# выполнить mysql-запрос с уже подобранными кредами; вернуть (ок, вывод)
def mysql_query(ctx, container, sql):
    creds = probe_mysql_credentials(ctx, container)
    if creds is None:
        return False, "не удалось подобрать креды mysql (env, секреты, values)"

    rc, out = mysql_query_raw(container, creds[0], creds[1], sql)
    if rc != 0:
        return False, out.strip()

    return True, out


# ---ЗАГРУЗКА VALUES---#

# загрузить values: базовый src/values.yaml + файл окружения (общая логика tools/common.py)
def load_values(ctx):
    values_dict, env_values_path, error_text = load_values_common(
        ctx.installer_dir, ctx.environment, ctx.values_name
    )

    if error_text:
        ctx.values_file_path = None
        return error_text

    ctx.values = values_dict
    ctx.values_file_path = str(env_values_path)
    ctx.values_loaded = True
    return None


# ---ПРОВЕРКИ: КОНФИГУРАЦИЯ---#

@check("config", "values-файл окружения")
def check_values_file(ctx):
    if not ctx.values_loaded:
        ctx.record("config", "values-файл окружения", STATUS_FAIL,
                   "values не загружены: %s; проверки идут без сверки с конфигом" % ctx.values_error)
        return

    ctx.record("config", "values-файл окружения", STATUS_OK,
               "загружен %s (root_mount_path=%s, host=%s)" % (
                   Path(ctx.values_file_path).name,
                   ctx.value("root_mount_path"),
                   ctx.value("host"),
               ))


@check("config", "security.yaml")
def check_security_file(ctx):
    security_path = Path("%s/security.yaml" % ctx.value("root_mount_path", ""))

    if not ctx.value("root_mount_path"):
        ctx.record("config", "security.yaml", STATUS_SKIP, "root_mount_path неизвестен (values не загружены)")
        return

    if not security_path.exists():
        ctx.record("config", "security.yaml", STATUS_FAIL, "не найден %s — окружение было развернуто?" % security_path)
        return

    ctx.record("config", "security.yaml", STATUS_OK, "найден: %s" % security_path)


@check("config", "версия инсталлятора")
def check_version_file(ctx):
    version_path = Path(ctx.installer_dir + "/.version")
    version = version_path.read_text().strip() if version_path.exists() else ""

    # git-состояние каталога инсталлятора: ветка и последний коммит (контекст для поддержки)
    git_parts = []
    rc, out, _ = run_cmd(["git", "-C", ctx.installer_dir, "branch", "--show-current"], timeout=15)
    if rc == 0 and out.strip():
        git_parts.append("ветка %s" % out.strip())
    rc, out, _ = run_cmd(["git", "-C", ctx.installer_dir, "log", "--oneline", "-1"], timeout=15)
    if rc == 0 and out.strip():
        git_parts.append(out.strip())

    if not version:
        message = "файл .version не найден — обновления через installer_migrations_up.py не отслеживаются"
        if git_parts:
            message += " (git: %s)" % ", ".join(git_parts)
        ctx.record("config", "версия инсталлятора", STATUS_WARN, message)
        return

    message = version
    if git_parts:
        message += " (git: %s)" % ", ".join(git_parts)
    ctx.record("config", "версия инсталлятора", STATUS_OK, message)


@check("config", "завершённость установки")
def check_install_steps(ctx):
    if not ctx.installer_dir:
        ctx.record("config", "завершённость установки", STATUS_SKIP, "каталог инсталлятора не найден")
        return

    steps_path = Path(ctx.installer_dir) / ".install_completed_steps.json"
    if not steps_path.exists():
        ctx.record("config", "завершённость установки", STATUS_SKIP,
                   "файл шагов установки не найден (установлено до появления трекинга шагов)")
        return

    try:
        steps = json.loads(steps_path.read_text(encoding="utf-8"))
    except Exception as e:
        ctx.record("config", "завершённость установки", STATUS_WARN, "файл шагов не читается: %s" % e)
        return
    if not isinstance(steps, list):
        steps = []

    # обязательные шаги install.py (activate_server опционален — локальная лицензия)
    required = ["intall_monolith", "init_monolith", "create_team"]
    missing = [step for step in required if step not in steps]

    if missing:
        ctx.record("config", "завершённость установки", STATUS_WARN,
                   "установка не завершена — нет шагов: %s (окружение может быть недоразвёрнуто)" % ", ".join(missing))
    elif steps:
        ctx.record("config", "завершённость установки", STATUS_OK, "все шаги выполнены (%s)" % ", ".join(steps))
    else:
        ctx.record("config", "завершённость установки", STATUS_OK, "все шаги выполнены")


@check("config", "каталог данных")
def check_data_dir(ctx):
    root_mount_path = ctx.value("root_mount_path")
    if not root_mount_path:
        ctx.record("config", "каталог данных", STATUS_SKIP, "root_mount_path неизвестен (values не загружены)")
        return

    if Path(root_mount_path).is_dir():
        ctx.record("config", "каталог данных", STATUS_OK, root_mount_path)
    else:
        ctx.record("config", "каталог данных", STATUS_FAIL, "каталог %s не существует" % root_mount_path)


@check("config", "стеки swarm vs конфиг")
def check_stacks_vs_config(ctx):
    expected = []
    monolith_label = ctx.value("projects.monolith.label")
    if monolith_label:
        expected.append("%s-%s" % (ctx.stack_prefix, monolith_label))

    domino_projects = ctx.value("projects.domino", {}) or {}
    if isinstance(domino_projects, dict):
        for domino_config in domino_projects.values():
            label = (domino_config or {}).get("label")
            if label:
                expected.append("%s-%s-company" % (ctx.stack_prefix, label))

    actual = ctx.stacks()

    for stack_name in expected:
        if stack_name in actual:
            ctx.record("config", "стек %s" % stack_name, STATUS_OK, "развернут")
        else:
            ctx.record("config", "стек %s" % stack_name, STATUS_FAIL, "ожидается из values, но не найден в docker stack ls")

    for stack_name in actual:
        if stack_name not in expected:
            ctx.record("config", "стек %s" % stack_name, STATUS_WARN,
                       "есть в swarm, но не выводится из values (лишний или values неполные)")


# ---ПРОВЕРКИ: ИНФРАСТРУКТУРА---#

@check("infra", "docker daemon")
def check_docker_daemon(ctx):
    client = ctx.docker()
    if client is None:
        ctx.record("infra", "docker daemon", STATUS_FAIL, "нет доступа к docker: %s" % ctx.docker_error)
        return

    try:
        info = client.info()
    except Exception as e:
        ctx.record("infra", "docker daemon", STATUS_FAIL, "docker info: %s" % e)
        return

    ctx.record("infra", "docker daemon", STATUS_OK,
               "server %s, контейнеров: running=%s, paused=%s, stopped=%s" % (
                   info.get("ServerVersion"),
                   info.get("ContainersRunning"),
                   info.get("ContainersPaused"),
                   info.get("ContainersStopped"),
               ))


@check("infra", "swarm")
def check_swarm(ctx):
    client = ctx.docker()
    if client is None:
        ctx.record("infra", "swarm", STATUS_SKIP, "docker недоступен")
        return

    try:
        info = client.info()
    except Exception as e:
        ctx.record("infra", "swarm", STATUS_FAIL, "docker info: %s" % e)
        return

    node_state = (info.get("Swarm") or {}).get("LocalNodeState")
    if node_state != "active":
        ctx.record("infra", "swarm", STATUS_FAIL, "swarm не активен (LocalNodeState=%s)" % node_state)
        return

    errors = (info.get("Swarm") or {}).get("Error") or ""
    if errors:
        ctx.record("infra", "swarm", STATUS_FAIL, "ошибка swarm: %s" % errors)
        return

    ctx.record("infra", "swarm", STATUS_OK, "активен (%s)" % ((info.get("Swarm") or {}).get("ControlAvailable")
                                                              and "менеджер" or "воркер"))


@check("infra", "место, занятое docker")
def check_docker_usage(ctx):
    rc, out, err = run_cmd(["docker", "system", "df"], timeout=60)
    if rc != 0:
        ctx.record("infra", "место, занятое docker", STATUS_SKIP,
                   "docker system df не выполнился: %s" % err.strip()[:200])
        return

    # строки таблицы: Images / Containers / Local Volumes / Build Cache
    parts = []
    for line in out.splitlines():
        fields = [field.strip() for field in line.split(maxsplit=5)]
        if len(fields) >= 3 and fields[0] in ("Images:", "Containers:", "Local", "Build"):
            label = fields[0].rstrip(":") + (" " + fields[1] if fields[0] == "Local" else "")
            size_index = 3 if fields[0] == "Local" else 2
            parts.append("%s: %s" % (label.rstrip(), fields[size_index] if len(fields) > size_index else "?"))

    if not parts:
        ctx.record("infra", "место, занятое docker", STATUS_OK, out.strip().replace("\n", "; ")[:200])
    else:
        ctx.record("infra", "место, занятое docker", STATUS_OK, ", ".join(parts))


@check("infra", "ноды swarm")
def check_nodes(ctx):
    try:
        nodes = docker_cli_json(["node", "ls"])
    except Exception as e:
        ctx.record("infra", "ноды swarm", STATUS_FAIL, str(e))
        return

    if not nodes:
        ctx.record("infra", "ноды swarm", STATUS_WARN, "docker node ls вернул пусто")
        return

    for node in nodes:
        name = node.get("Hostname", "?")
        # поле Status может быть строкой ("Ready") или словарём ({"State": ...}) в зависимости от версии docker
        node_status = node.get("Status", "?")
        if isinstance(node_status, dict):
            state = node_status.get("State", "?")
        else:
            state = node_status
        availability = node.get("Availability", "?")
        if str(state).lower() != "ready":
            ctx.record("infra", "нода %s" % name, STATUS_FAIL, "состояние %s" % state)
        elif availability == "drain":
            ctx.record("infra", "нода %s" % name, STATUS_WARN, "переведена в drain")
        else:
            ctx.record("infra", "нода %s" % name, STATUS_OK, "%s/%s (manager=%s)" % (
                state, availability, node.get("ManagerStatus", "-") or "нет"))


@check("infra", "дисковое пространство")
def check_disk(ctx):
    paths = ["/", ctx.value("root_mount_path"), "/var/lib/docker"]
    seen_devices = set()

    for path in paths:
        if not path or not Path(path).exists():
            continue
        try:
            stat = os.statvfs(path)
            device_id = os.stat(path).st_dev
        except OSError as e:
            ctx.record("infra", "диск %s" % path, STATUS_WARN, "statvfs: %s" % e)
            continue

        if device_id in seen_devices:
            continue
        seen_devices.add(device_id)

        free_percent = 100.0 * stat.f_bavail / stat.f_blocks if stat.f_blocks else 0
        free_gb = stat.f_bavail * stat.f_frsize / 1024 ** 3

        if free_percent < DISK_FREE_FAIL_PERCENT:
            status = STATUS_FAIL
        elif free_percent < DISK_FREE_WARN_PERCENT:
            status = STATUS_WARN
        else:
            status = STATUS_OK

        # иноды: переполнение ломает запись даже при свободном месте
        inode_text = ""
        if stat.f_files:
            inode_free_percent = 100.0 * stat.f_ffree / stat.f_files
            inode_text = ", иноды свободно %.1f%%" % inode_free_percent
            if inode_free_percent < DISK_FREE_FAIL_PERCENT:
                status = STATUS_FAIL
            elif inode_free_percent < DISK_FREE_WARN_PERCENT and status != STATUS_FAIL:
                status = STATUS_WARN

        ctx.record("infra", "диск %s" % path, status,
                   "свободно %.1f%% (%.1f ГБ)%s" % (free_percent, free_gb, inode_text))


@check("infra", "память")
def check_memory(ctx):
    meminfo_path = Path("/proc/meminfo")
    if not meminfo_path.exists():
        ctx.record("infra", "память", STATUS_SKIP, "/proc/meminfo недоступен (не linux?)")
        return

    meminfo = {}
    for line in meminfo_path.read_text().splitlines():
        parts = line.split(":", 1)
        if len(parts) == 2:
            meminfo[parts[0].strip()] = int(parts[1].strip().split()[0])

    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    if total == 0:
        ctx.record("infra", "память", STATUS_WARN, "не удалось прочитать MemTotal")
        return

    free_percent = 100.0 * available / total
    if free_percent < 5:
        status = STATUS_FAIL
    elif free_percent < 10:
        status = STATUS_WARN
    else:
        status = STATUS_OK

    ctx.record("infra", "память", status,
               "доступно %.1f%% (%.1f ГБ из %.1f ГБ)" % (free_percent, available / 1024 ** 2, total / 1024 ** 2))


@check("infra", "load average")
def check_load(ctx):
    loadavg_path = Path("/proc/loadavg")
    if not loadavg_path.exists():
        ctx.record("infra", "load average", STATUS_SKIP, "/proc/loadavg недоступен (не linux?)")
        return

    try:
        load_1min = float(loadavg_path.read_text().split()[0])
    except (ValueError, IndexError):
        ctx.record("infra", "load average", STATUS_WARN, "не удалось разобрать /proc/loadavg")
        return

    cpu_count = os.cpu_count() or 1
    if load_1min > cpu_count * 4:
        status = STATUS_FAIL
    elif load_1min > cpu_count * 2:
        status = STATUS_WARN
    else:
        status = STATUS_OK

    ctx.record("infra", "load average", status, "load1=%.2f (cpu=%d)" % (load_1min, cpu_count))


# ---ПРОВЕРКИ: СЕРВИСЫ---#

# имя сервиса для краткости в отчёте: "monolith/nginx-monolith" вместо полного имени стека
def short_service_name(ctx, stack, service_name):
    short_stack = stack
    if ctx.stack_prefix and stack.startswith(ctx.stack_prefix + "-"):
        short_stack = stack[len(ctx.stack_prefix) + 1:]

    short_name = service_name
    if service_name.startswith(stack + "_"):
        short_name = service_name[len(stack) + 1:]

    return "%s/%s" % (short_stack, short_name)


# рестарт-политика сервиса ("none" = run-once сервис, ему нормально быть 0/1)
def service_restart_condition(service_name):
    try:
        items = docker_cli_json(["service", "inspect", service_name], timeout=30)
        for item in items:
            condition = ((((item or {}).get("Spec") or {}).get("TaskTemplate") or {}).get("RestartPolicy") or {})
            return condition.get("Condition", "")
    except Exception:
        pass
    return ""


@check("services", "реплики сервисов")
def check_service_replicas(ctx):
    for stack in ctx.stacks():
        try:
            services = ctx.stack_services(stack)
        except Exception as e:
            ctx.record("services", "стек %s" % stack, STATUS_FAIL, "docker stack services: %s" % e)
            continue

        if not services:
            ctx.record("services", "стек %s" % stack, STATUS_FAIL, "в стеке нет сервисов")
            continue

        for service in services:
            name = service.get("Name", "?")
            replicas_raw = str(service.get("Replicas", "?/?"))
            short_name = short_service_name(ctx, stack, name)

            try:
                running, desired = [int(part) for part in replicas_raw.split("/")]
            except ValueError:
                ctx.record("services", short_name, STATUS_WARN, "не разобрать состояние реплик: %r" % replicas_raw)
                continue

            if running >= desired and desired > 0:
                ctx.record("services", short_name, STATUS_OK, "%d/%d" % (running, desired))
                continue

            if desired == 0:
                ctx.record("services", short_name, STATUS_WARN, "масштаб 0 (приостановлен?)")
                continue

            # 0/1 бывает нормой у run-once сервисов (default-file, jitsi-custom и т.п.)
            if any(prefix in name for prefix in RUN_ONCE_SERVICE_PREFIXES) or \
                    service_restart_condition(name) == "none":
                ctx.record("services", short_name, STATUS_OK, "run-once сервис (%s)" % replicas_raw)
                continue

            ctx.record("services", short_name, STATUS_FAIL, "запущено %d из %d" % (running, desired))


# короткое имя контейнера: убираем префикс стека и суффикс задачи .<slot>.<id>
def short_container_name(ctx, stack, container_name):
    base = container_name.split(".", 1)[0]
    return short_service_name(ctx, stack, base)


@check("services", "health и рестарты контейнеров")
def check_containers_health(ctx):
    for stack in ctx.stacks():
        containers = ctx.stack_containers(stack)
        healthy_count = 0
        has_problems = False

        for container in containers:
            name = short_container_name(ctx, stack, container.name)
            state = container.attrs.get("State", {})
            status = state.get("Status", "?")

            # это текущая задача сервиса — проверяем health
            if status == "running":
                health = (state.get("Health") or {}).get("Status")
                if health == "unhealthy":
                    has_problems = True
                    ctx.record("services", name, STATUS_FAIL, "healthcheck: unhealthy")
                elif health == "starting":
                    has_problems = True
                    ctx.record("services", name, STATUS_WARN, "healthcheck: starting (ещё поднимается)")
                elif health == "healthy":
                    healthy_count += 1

            if state.get("OOMKilled"):
                has_problems = True
                ctx.record("services", name, STATUS_FAIL, "контейнер убит по OOM")

            restart_count = container.attrs.get("RestartCount", 0)
            if restart_count >= RESTART_FAIL_COUNT:
                has_problems = True
                ctx.record("services", name, STATUS_FAIL, "рестартов: %d" % restart_count)
            elif restart_count >= RESTART_WARN_COUNT:
                has_problems = True
                ctx.record("services", name, STATUS_WARN, "рестартов: %d" % restart_count)

        # если всё хорошо — не шумим списком контейнеров, выводим агрегат
        if healthy_count and not has_problems:
            short_stack = stack[len(ctx.stack_prefix) + 1:] if stack.startswith(ctx.stack_prefix + "-") else stack
            ctx.record("services", "контейнеры %s" % short_stack, STATUS_OK,
                       "%d healthy, проблемных healthcheck/OOM/рестартов нет" % healthy_count)


@check("services", "упавшие задачи за период")
def check_service_tasks(ctx):
    since_seconds = parse_since_period(args.since)

    for stack in ctx.stacks():
        for service in ctx.stack_services(stack):
            name = service.get("Name", "?")
            short_name = short_service_name(ctx, stack, name)
            try:
                # истории задач немного (retention swarm), фильтруем по возрасту сами
                tasks = docker_cli_json(
                    ["service", "ps", name],
                    timeout=60,
                )
            except Exception as e:
                ctx.record("services", short_name, STATUS_WARN, "service ps: %s" % e)
                continue

            problems = []
            for task in tasks:
                error = task.get("Error", "") or ""
                desired_state = task.get("DesiredState", "")
                current_state = task.get("CurrentState", "")
                age_seconds = parse_current_state_age(current_state)

                # учитываем только события за интересующий период
                if age_seconds is None or age_seconds > since_seconds:
                    continue

                # упавшие с ненулевым кодом
                match = re.search(r"non-zero exit \((\d+)\)", error)
                if match:
                    problems.append("задача упала с кодом %d" % int(match.group(1)))
                    continue

                # задача не в Running, хотя должна
                if desired_state == "Running" and current_state not in (
                        "Running", "Starting", "Pending", "Preparing", "Assigned", "Accepted"):
                    problems.append("DesiredState=Running, CurrentState=%s %s" % (current_state, error))

            if problems:
                # 137/255/139 — OOM и фатальные коды, остальное хотя бы предупреждём
                has_fatal = any(re.search(r"код (137|255|139)", item) for item in problems)
                status = STATUS_FAIL if has_fatal or len(problems) >= 3 else STATUS_WARN
                ctx.record("services", short_name, status, "; ".join(problems[:5]))


@check("services", "условные сервисы vs конфиг")
def check_conditional_services(ctx):
    if not ctx.values_loaded:
        ctx.record("services", "условные сервисы vs конфиг", STATUS_SKIP, "values не загружены")
        return

    monolith_stack = "%s-%s" % (ctx.stack_prefix, ctx.value("projects.monolith.label", "monolith"))
    if monolith_stack not in ctx.stacks():
        ctx.record("services", "условные сервисы vs конфиг", STATUS_SKIP, "стек %s не найден" % monolith_stack)
        return

    try:
        service_names = [service.get("Name", "") for service in ctx.stack_services(monolith_stack)]
    except Exception as e:
        ctx.record("services", "условные сервисы vs конфиг", STATUS_FAIL, str(e))
        return

    # условные сервисы: должны присутствовать в стеке тогда и только тогда, когда включены в values
    expectations = [
        ("kafka", ctx.value("siem.enabled_driver") == "kafka",
         "siem.enabled_driver=%s" % (ctx.value("siem.enabled_driver") or "none")),
        ("outlook_add_in-", bool(ctx.value("projects.outlook_add_in.is_enabled")), "outlook_add_in.is_enabled"),
        ("go-local-license-", bool(ctx.value("local_license")), "local_license"),
        ("go-license-manager-", bool(ctx.value("local_license")), "local_license"),
        ("go-file-auth-", ctx.value("file_access_restriction_mode") == "auth", "file_access_restriction_mode=auth"),
    ]

    for prefix, should_exist, config_hint in expectations:
        exists = any(prefix in name for name in service_names)
        if should_exist and not exists:
            ctx.record("services", "сервис *%s*" % prefix, STATUS_FAIL,
                       "включён в конфиге (%s), но сервиса нет в стеке" % config_hint)
        elif not should_exist and exists:
            ctx.record("services", "сервис *%s*" % prefix, STATUS_WARN,
                       "есть в стеке, но выключен в конфиге (%s) — вероятно, нужен redeploy" % config_hint)
        else:
            ctx.record("services", "сервис *%s*" % prefix, STATUS_OK, "соответствует конфигу (%s)" % config_hint)


@check("services", "rabbitmq: живость и очереди")
def check_rabbit(ctx):
    monolith_label = ctx.value("projects.monolith.label", "monolith")
    stack = "%s-%s" % (ctx.stack_prefix, monolith_label)
    if stack not in ctx.stacks():
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_SKIP, "стек %s не найден" % stack)
        return

    containers = find_containers(ctx, stack, "rabbit-")
    if not containers:
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_FAIL, "контейнер rabbit не найден")
        return
    container = containers[0]

    rc, out = exec_in_container(container, "rabbitmqctl ping", timeout=30)
    if rc != 0:
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_FAIL, "rabbitmqctl ping: %s" % out.strip()[:200])
        return

    rc, out = exec_in_container(
        container,
        "rabbitmqctl list_queues --formatter json name messages messages_ready messages_unacknowledged consumers",
        timeout=60,
    )
    queues = []
    try:
        # вывод может содержать служебные строки перед json
        json_start = out.index("[")
        queues = json.loads(out[json_start:])
    except (ValueError, IndexError):
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_WARN,
                   "жив, но не удалось разобрать list_queues: %s" % out.strip()[:200])
        return

    total_messages = 0
    stuck = []      # очереди с сообщениями и без потребителей
    backlog = []    # очереди с большим неподобранным backlog
    for queue in queues:
        ready = int(queue.get("messages_ready", 0) or 0)
        unacked = int(queue.get("messages_unacknowledged", 0) or 0)
        consumers = int(queue.get("consumers", 0) or 0)
        total_messages += int(queue.get("messages", 0) or 0)

        if consumers == 0 and ready > 100:
            stuck.append("%s (ready=%d, потребителей нет)" % (queue.get("name", "?"), ready))
        elif ready > RABBIT_QUEUE_BACKLOG_WARN:
            backlog.append("%s (ready=%d)" % (queue.get("name", "?"), ready))
        if unacked > RABBIT_QUEUE_BACKLOG_WARN:
            backlog.append("%s (unacked=%d)" % (queue.get("name", "?"), unacked))

    summary = "жив, очередей: %d, сообщений всего: %d" % (len(queues), total_messages)
    if stuck:
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_FAIL,
                   "%s; очереди без потребителей: %s — сервисы не разбирают очередь (проверьте go_sender/go_event)" % (
                       summary, "; ".join(stuck[:4])))
    elif backlog:
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_WARN,
                   "%s; растущий backlog: %s" % (summary, "; ".join(backlog[:4])))
    else:
        ctx.record("services", "rabbitmq: живость и очереди", STATUS_OK, summary)


@check("services", "memcached: кэш")
def check_memcached(ctx):
    monolith_label = ctx.value("projects.monolith.label", "monolith")
    stack = "%s-%s" % (ctx.stack_prefix, monolith_label)
    if stack not in ctx.stacks():
        ctx.record("services", "memcached: кэш", STATUS_SKIP, "стек %s не найден" % stack)
        return

    php_containers = find_containers(ctx, stack, "php-monolith")
    if not php_containers:
        ctx.record("services", "memcached: кэш", STATUS_SKIP, "нет php-контейнера для проверки")
        return

    # стучимся из php-контейнера (в образе memcached нет инструментов);
    # fsockopen в php-образе Compass отключён (disable_functions) — используем stream_socket_client
    memcached_host = "memcached-%s" % monolith_label
    php_code = (
        '$s=@stream_socket_client("tcp://%s:11211",$errno,$errstr,3);'
        'if(!$s){echo "CONNFAIL ".$errstr;exit(1);}'
        'fwrite($s,"version\r\nstats\r\nquit\r\n");'
        'echo stream_get_contents($s);'
    ) % memcached_host
    rc, out = exec_in_container(php_containers[0], "php -r %s" % shlex.quote(php_code), timeout=30)

    if rc != 0 or "CONNFAIL" in out:
        ctx.record("services", "memcached: кэш", STATUS_FAIL,
                   "%s:%d не отвечает из php-контейнера: %s" % (memcached_host, 11211, out.strip()[:200]))
        return

    version = re.search(r"VERSION\s+([\d.]+)", out)
    curr_items = re.search(r"STAT curr_items (\d+)", out)
    evictions = re.search(r"STAT evictions (\d+)", out)
    bytes_used = re.search(r"STAT bytes (\d+)", out)
    max_bytes = re.search(r"STAT limit_maxbytes (\d+)", out)

    parts = ["жив (v%s), объектов: %s" % (
        version.group(1) if version else "?",
        curr_items.group(1) if curr_items else "?",
    )]
    if bytes_used and max_bytes and int(max_bytes.group(1)):
        fill = 100.0 * int(bytes_used.group(1)) / int(max_bytes.group(1))
        parts.append("заполнен %.0f%%" % fill)
    else:
        fill = 0

    evictions_count = int(evictions.group(1)) if evictions else 0
    if evictions_count > 0:
        ctx.record("services", "memcached: кэш", STATUS_WARN,
                   "%s, evictions: %d — кэш мал, данные вытесняются (падение производительности)" % (
                       ", ".join(parts), evictions_count))
    elif fill > 90:
        ctx.record("services", "memcached: кэш", STATUS_WARN, "%s — почти заполнен" % ", ".join(parts))
    else:
        ctx.record("services", "memcached: кэш", STATUS_OK, ", ".join(parts))


# послать websocket-upgrade на host:port/path; вернуть (код, первая строка ответа) или (None, ошибка)
def ws_upgrade_probe(host, port, path, sni_host=None):
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ) % (path, host, ws_key)
    try:
        raw_socket = socket.create_connection((host, port), timeout=args.http_timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_socket = context.wrap_socket(raw_socket, server_hostname=sni_host or host)
        tls_socket.settimeout(args.http_timeout)
        tls_socket.sendall(request.encode("ascii"))
        response = tls_socket.recv(256).decode("utf-8", "ignore")
        tls_socket.close()
    except Exception as e:
        return None, str(e)

    first_line = response.splitlines()[0] if response else ""
    code_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", first_line)
    return (int(code_match.group(1)) if code_match else None), first_line


@check("services", "websocket go_sender (realtime)")
def check_go_sender_ws(ctx):
    if not ctx.values_loaded or not ctx.value("host"):
        ctx.record("services", "websocket go_sender (realtime)", STATUS_SKIP, "values не загружены")
        return

    host = ctx.value("host")
    ws_port = int(ctx.value("nginx.websocket_port") or 0)
    if ws_port in (0, 80, 443):
        ws_port = main_external_port(ctx)

    # путь pivot /ws и /ws0, домино — /<label>/ws; нас устраивает любой, поднявший upgrade
    candidate_paths = ["/ws", "/ws0"]
    for domino_config in (ctx.value("projects.domino") or {}).values():
        label = (domino_config or {}).get("label") if isinstance(domino_config, dict) else None
        if label:
            candidate_paths.append("/%s/ws" % label)

    # проход 1: по host из values
    network_unreachable = True
    for path in candidate_paths:
        code, first_line = ws_upgrade_probe(host, ws_port, path)
        if code == 101:
            ctx.record("services", "websocket go_sender (realtime)", STATUS_OK,
                       "upgrade ок: %s:%d%s" % (host, ws_port, path))
            return
        if code is not None:
            network_unreachable = False  # host отвечает — просто путь не подошёл

    # проход 2: host из values недоступен — все пути локально, с SNI=host
    if network_unreachable:
        first_local = ""
        for path in candidate_paths:
            code_local, first_local = ws_upgrade_probe(
                "127.0.0.1", main_external_port(ctx), path, sni_host=host)
            if code_local == 101:
                ctx.record("services", "websocket go_sender (realtime)", STATUS_WARN,
                           "%s:%d%s — host из values недоступен, но локально upgrade проходит — проверьте доступность host" % (
                               host, ws_port, path))
                return
        ctx.record("services", "websocket go_sender (realtime)", STATUS_FAIL,
                   "websocket не поднимается: %s:%d недоступен (%s), локально на 127.0.0.1:%d ответ: %s — "
                   "realtime-доставка сообщений не работает" % (
                       host, ws_port, (first_line or "нет ответа")[:80], main_external_port(ctx),
                       (first_local or "нет ответа")[:80]))
        return

    ctx.record("services", "websocket go_sender (realtime)", STATUS_FAIL,
               "websocket не поднимается (%s:%d, ответ: %s) — realtime-доставка сообщений не работает" % (
                   host, ws_port, (first_line or "нет ответа")[:120]))


@check("services", "звонки: медиа-порт UDP jvb")
def check_calls_udp(ctx):
    media_port = int(ctx.value("projects.jitsi.service.jvb.media_port") or 10000)

    rc, out, _ = run_cmd(["ss", "-lun"], timeout=15)
    if rc != 0:
        ctx.record("services", "звонки: медиа-порт UDP jvb", STATUS_SKIP, "ss не выполнился")
        return

    # слушается ли порт на любом адресе (jvb работает в host-сети)
    if re.search(r":%d\s" % media_port, out):
        ctx.record("services", "звонки: медиа-порт UDP jvb", STATUS_OK, "UDP %d слушается (jvb)" % media_port)
    else:
        ctx.record("services", "звонки: медиа-порт UDP jvb", STATUS_FAIL,
                   "UDP %d не слушается — jvb не поднялся или порт закрыт; медиа в звонках не пойдёт" % media_port)


@check("services", "звонки: TURN")
def check_calls_turn(ctx):
    if not ctx.values_loaded:
        ctx.record("services", "звонки: TURN", STATUS_SKIP, "values не загружены")
        return

    turn_config = ctx.value("projects.jitsi.service.turn") or {}
    if not isinstance(turn_config, dict):
        turn_config = {}

    force_relay = bool(turn_config.get("force_relay", True))
    turn_host = turn_config.get("host") or ""
    turn_port = int(turn_config.get("port") or 3478)
    turn_tls_port = int(turn_config.get("tls_port") or 5349)

    if not turn_host:
        if force_relay:
            ctx.record("services", "звонки: TURN", STATUS_FAIL,
                       "force_relay=true (весь медиатрафик через TURN), но turn.host пуст — "
                       "медиа в звонках не пойдёт ни у кого; настройте coturn и заполните projects.jitsi.service.turn")
        else:
            ctx.record("services", "звонки: TURN", STATUS_SKIP,
                       "TURN не задан; при force_relay=false допустимо (прямой UDP к jvb)")
        return

    # доступность coturn по tcp с этого сервера
    reachable = []
    for port, label in ((turn_port, "tcp/%d" % turn_port), (turn_tls_port, "tcp/%d (tls)" % turn_tls_port)):
        try:
            probe = socket.create_connection((turn_host, port), timeout=args.http_timeout)
            probe.close()
            reachable.append(label)
        except Exception:
            pass

    if not reachable:
        status = STATUS_FAIL if force_relay else STATUS_WARN
        ctx.record("services", "звонки: TURN", status,
                   "%s не отвечает на %d и %d (tcp) — проверьте coturn и фаервол" % (
                       turn_host, turn_port, turn_tls_port))
    else:
        relay_note = ", весь медиатрафик идёт через него (force_relay=true)" if force_relay else ""
        ctx.record("services", "звонки: TURN", STATUS_OK,
                   "%s доступен (%s)%s" % (turn_host, ", ".join(reachable), relay_note))


@check("services", "образы сервисов vs values")
def check_images_vs_values(ctx):
    if not ctx.values_loaded:
        ctx.record("services", "образы сервисов vs values", STATUS_SKIP, "values не загружены")
        return

    # карта: нормализованный ключ сервиса (с дефисами) -> тег из values
    tag_map = {}
    for project_config in (ctx.value("projects") or {}).values():
        services = (project_config or {}).get("service") if isinstance(project_config, dict) else None
        if not isinstance(services, dict):
            continue
        for service_key, service_config in services.items():
            tag = service_config.get("tag") if isinstance(service_config, dict) else None
            if tag:
                tag_map[str(service_key).replace("_", "-")] = str(tag)

    if not tag_map:
        ctx.record("services", "образы сервисов vs values", STATUS_SKIP, "в values нет тегов сервисов")
        return

    mismatches = []
    checked = 0
    for stack in ctx.stacks():
        for service in ctx.stack_services(stack):
            short_name = short_service_name(ctx, stack, service.get("Name", ""))
            image = service.get("Image", "")
            if ":" not in image:
                continue

            # самый длинный ключ, входящий в имя сервиса (go-sender-balancer точнее go-sender)
            matched_key = None
            for key in sorted(tag_map, key=len, reverse=True):
                if key in short_name:
                    matched_key = key
                    break
            if matched_key is None:
                continue

            checked += 1
            image_tag = image.rsplit(":", 1)[1]
            if image_tag != tag_map[matched_key]:
                mismatches.append("%s: образ %s, values %s" % (short_name, image_tag, tag_map[matched_key]))

    if not checked:
        ctx.record("services", "образы сервисов vs values", STATUS_SKIP, "сопоставлений со значениями values не найдено")
    elif mismatches:
        ctx.record("services", "образы сервисов vs values", STATUS_WARN,
                   "запущенные образы отличаются от values (%d из %d): %s — redeploy не выполнен или откат" % (
                       len(mismatches), checked, "; ".join(mismatches[:5])))
    else:
        ctx.record("services", "образы сервисов vs values", STATUS_OK,
                   "все запущенные образы соответствуют values (%d сервисов)" % checked)


# ---ПРОВЕРКИ: HTTP---#

# базовый url главного nginx
def main_entry_url(ctx):
    port = main_external_port(ctx)
    host = ctx.value("host") or "localhost"
    protocol = ctx.value("protocol") or "https"
    port_suffix = "" if int(port) == 443 else ":%d" % int(port)
    return "%s://%s%s" % (protocol, host, port_suffix)


# внешний порт главного nginx (он же локальный порт для фолбэка)
def main_external_port(ctx):
    return int(ctx.value("projects.monolith.service.nginx.external_https_port") or 443)


# проверить http-доступность url; local_port — порт, опубликованный на хосте,
# по которому можно стучаться в обход values host (для диагностики "host не резолвится, но сервис жив")
def http_check(ctx, group, name, url, local_port=None):
    try:
        response = requests.get(
            url,
            verify=False,
            timeout=args.http_timeout,
            allow_redirects=True,
        )
    except Exception as e:
        # host из values недоступен — проверяем, отвечает ли сервис локально по опубликованному порту
        if local_port:
            local_result = http_probe_local(url, local_port)
            if local_result is not None:
                ctx.record(group, name, STATUS_WARN,
                           "%s — host из values недоступен (%s), но локально на 127.0.0.1:%d отвечает кодом %d; "
                           "проверьте доступность host" % (url, error_summary(str(e)), local_port, local_result))
                return None

        ctx.record(group, name, STATUS_FAIL, "%s — недоступен: %s" % (url, error_summary(str(e))))
        return None

    if response.status_code >= 500:
        ctx.record(group, name, STATUS_FAIL, "%s — код %d" % (url, response.status_code))
    elif response.status_code == 404:
        # 404 на пути проекта часто значит, что location не сконфигурирован в nginx
        ctx.record(group, name, STATUS_WARN, "%s — код 404 (путь не настроен в nginx?)" % url)
    else:
        ctx.record(group, name, STATUS_OK, "%s — код %d" % (url, response.status_code))
    return response


# постучаться в url через 127.0.0.1:local_port с оригинальным заголовком Host; вернуть код или None
def http_probe_local(url, local_port):
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    local_url = "%s://127.0.0.1:%d%s" % (parts.scheme, local_port, parts.path or "/")
    try:
        response = requests.get(
            local_url,
            verify=False,
            timeout=args.http_timeout,
            allow_redirects=False,
            headers={"Host": parts.netloc},
        )
        return response.status_code
    except Exception:
        return None


# первая строка текста (для кратких сообщений об ошибках)
def first_line(text):
    return text.splitlines()[0] if text else ""


# краткое описание сетевой ошибки: достаём [Errno N] описание или берём первую строку
def error_summary(text):
    match = re.search(r"\[Errno \d+\]\s*[A-Za-z][A-Za-z ]*", text)
    if match:
        return match.group(0).strip()
    return first_line(text)[:120]


@check("http", "главная страница")
def check_http_main(ctx):
    if not ctx.values_loaded:
        ctx.record("http", "главная страница", STATUS_SKIP, "values не загружены")
        return

    http_check(ctx, "http", "главная страница", main_entry_url(ctx) + "/", local_port=main_external_port(ctx))


@check("http", "пути проектов через nginx")
def check_http_paths(ctx):
    if not ctx.values_loaded:
        ctx.record("http", "пути проектов через nginx", STATUS_SKIP, "values не загружены")
        return

    # проекты, доступные через главный nginx по url_path
    path_projects = ["pivot", "announcement", "federation", "userbot", "integration"]
    if ctx.value("local_license"):
        path_projects.append("license")

    domino_projects = ctx.value("projects.domino", {}) or {}
    if isinstance(domino_projects, dict):
        for domino_config in domino_projects.values():
            if domino_config.get("url_path"):
                path_projects.append("domino:%s" % domino_config.get("url_path"))

    base_url = main_entry_url(ctx)

    for item in path_projects:
        if item.startswith("domino:"):
            name = "domino"
            url_path = item.split(":", 1)[1]
        else:
            name = item
            url_path = ctx.value("projects.%s.url_path" % item)

        if not url_path:
            continue

        http_check(ctx, "http", "путь /%s" % url_path, "%s/%s/" % (base_url, url_path),
                   local_port=main_external_port(ctx))


@check("http", "api_gateway /health")
def check_http_api_gateway(ctx):
    if not ctx.values_loaded:
        ctx.record("http", "api_gateway /health", STATUS_SKIP, "values не загружены")
        return

    gateway_id = ctx.value("api_gateway_id", "gateway-1")
    port = ctx.value("projects.api_gateway.%s.service.go_api_gateway.external_https_port" % gateway_id)
    if not port:
        ctx.record("http", "api_gateway /health", STATUS_SKIP, "порт api_gateway не задан в values")
        return

    host = ctx.value("host") or "localhost"
    http_check(ctx, "http", "api_gateway /health", "https://%s:%d/health" % (host, int(port)), local_port=int(port))


@check("http", "сертификаты TLS")
def check_certificates(ctx):
    # локальные файлы сертификатов
    ssl_dir = Path("%s/nginx/ssl" % (ctx.value("root_mount_path") or ""))
    cert_paths = []
    if ssl_dir.is_dir():
        cert_paths = sorted(list(ssl_dir.glob("*.crt")) + list(ssl_dir.glob("*.pem")))

    if not cert_paths and not ctx.values_loaded:
        ctx.record("http", "сертификаты TLS", STATUS_SKIP, "values не загружены, каталог сертификатов не найден")
        return

    for cert_path in cert_paths:
        days_left = certificate_days_left_file(cert_path)
        record_cert_result(ctx, "сертификат %s" % cert_path.name, days_left)

    # сертификат, который реально отдаёт главный nginx
    if ctx.values_loaded and ctx.value("host"):
        port = int(ctx.value("projects.monolith.service.nginx.external_https_port") or 443)
        days_left = certificate_days_left_remote(ctx.value("host"), port)
        if days_left is not None:
            record_cert_result(ctx, "сертификат на входе (%s:%d)" % (ctx.value("host"), port), days_left)


# сколько дней осталось у сертификата в файле
def certificate_days_left_file(cert_path):
    rc, out, err = run_cmd(
        ["openssl", "x509", "-noout", "-enddate", "-in", str(cert_path)],
        timeout=15,
    )
    if rc != 0:
        return None
    return parse_openssl_enddate(out)


# сколько дней осталось у сертификата, который отдаёт host:port
def certificate_days_left_remote(host, port):
    try:
        ctx_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=args.http_timeout) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
        if not der_cert:
            return None
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    except Exception:
        return None

    rc, out, err = run_cmd(
        ["openssl", "x509", "-noout", "-enddate"],
        timeout=15,
        input_bytes=pem_cert.encode("utf-8"),
    )
    if rc != 0:
        return None
    return parse_openssl_enddate(out)


# разобрать вывод "notAfter=Aug 30 12:00:00 2026 GMT"
def parse_openssl_enddate(text):
    for line in text.splitlines():
        if line.startswith("notAfter="):
            raw = line.split("=", 1)[1].strip()
            try:
                expires = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except ValueError:
                return None
            return (expires - datetime.now(timezone.utc)).days
    return None


# записать результат проверки сертификата
def record_cert_result(ctx, name, days_left):
    if days_left is None:
        ctx.record("http", name, STATUS_WARN, "не удалось определить срок действия")
        return

    if days_left < CERT_FAIL_DAYS:
        status = STATUS_FAIL
    elif days_left < CERT_WARN_DAYS:
        status = STATUS_WARN
    else:
        status = STATUS_OK

    ctx.record("http", name, status, "истекает через %d дн." % days_left)


# ---ПРОВЕРКИ: БЕЗОПАСНОСТЬ---#

# загрузить сырой файл окружения (без мерджа с базовым) — для поиска дефолтов, которые не сменили
def load_env_values_raw(ctx):
    if not ctx.values_file_path:
        return {}
    try:
        import yaml

        return yaml.safe_load(Path(ctx.values_file_path).read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


@check("security", "пароли по умолчанию")
def check_security_passwords(ctx):
    if not ctx.values_loaded:
        ctx.record("security", "пароли по умолчанию", STATUS_SKIP, "values не загружены")
        return

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

    walk(load_env_values_raw(ctx), "")

    # и критичные пути из смёрженного конфига (могут прийти из базового файла)
    for critical_path in (
            "projects.pivot.service.mysql.root_password",
            "projects.monolith.service.mysql.root_password",
            "projects.kafka.service.kafka.password",
    ):
        value = ctx.value(critical_path)
        if value in DEFAULT_PASSWORDS:
            entry = (critical_path, value)
            if entry not in findings:
                findings.append(entry)

    if findings:
        details = "; ".join("%s=%s" % (path, value) for path, value in findings[:6])
        ctx.record("security", "пароли по умолчанию", STATUS_FAIL,
                   "в values остались пароли из шаблона (%d): %s — смените в файле окружения "
                   "values и перерендерьте конфиги" % (len(findings), details))
    else:
        ctx.record("security", "пароли по умолчанию", STATUS_OK, "паролей-плейсхолдеров в values не найдено")


@check("security", "плейсхолдеры конфигурации")
def check_security_placeholders(ctx):
    if not ctx.values_loaded:
        ctx.record("security", "плейсхолдеры конфигурации", STATUS_SKIP, "values не загружены")
        return

    problems = []

    host = ctx.value("host")
    if host in (None, "", "example.com"):
        problems.append("host=%r (плейсхолдер)" % host)

    jitsi_app_secret = ctx.value("projects.jitsi.jwt.app_secret")
    if not jitsi_app_secret:
        problems.append("projects.jitsi.jwt.app_secret пуст — конференции без подписи JWT")

    auth_secret = ctx.value("projects.auth.service.go_auth.secret_key_b64")
    if auth_secret == "":
        problems.append("projects.auth...secret_key_b64 пуст — go-auth работает без ключа")

    if problems:
        ctx.record("security", "плейсхолдеры конфигурации", STATUS_WARN, "; ".join(problems))
    else:
        ctx.record("security", "плейсхолдеры конфигурации", STATUS_OK, "не найдены")


# какие порты ожидаются опубликованными наружу согласно values
@check("security", "опубликованные порты")
def check_security_ports(ctx):
    rc, out, err = run_cmd(["docker", "service", "ls", "--format", "{{.Name}}|{{.Ports}}"], timeout=60)
    if rc != 0:
        ctx.record("security", "опубликованные порты", STATUS_SKIP,
                   "docker service ls не выполнился: %s" % err.strip()[:200])
        return

    expected = set()

    def add_expected(port):
        try:
            if port:
                expected.add(int(port))
        except (TypeError, ValueError):
            pass

    if ctx.values_loaded:
        add_expected(ctx.value("projects.monolith.service.nginx.external_https_port"))
        add_expected(ctx.value("projects.monolith.service.nginx.external_http_port"))
        add_expected(ctx.value("projects.auth.service.go_auth.external_grpc_port"))
        add_expected(ctx.value("projects.join_web.service.join_web.external_port"))
        add_expected(ctx.value("projects.jitsi_web.service.jitsi_web.external_port"))
        if ctx.value("projects.outlook_add_in.is_enabled"):
            add_expected(ctx.value("projects.outlook_add_in.service.external_port"))
        if ctx.value("siem.enabled_driver") == "kafka":
            add_expected(ctx.value("projects.kafka.service.kafka.external_port"))
            add_expected(ctx.value("siem.driver_data.listen_port"))

        gateway_id = ctx.value("api_gateway_id", "gateway-1")
        add_expected(ctx.value("projects.api_gateway.%s.service.go_api_gateway.external_https_port" % gateway_id))

        # jitsi: веб, jicofo и просоди (включая версии компонент v0/v1/v2)
        add_expected(ctx.value("projects.jitsi.service.web.https_port"))
        add_expected(ctx.value("projects.jitsi.service.web.http_port"))
        add_expected(ctx.value("projects.jitsi.service.jicofo.port"))
        add_expected(ctx.value("projects.jitsi.service.prosody.serve_port"))
        for suffix in ("", ".v0", ".v1", ".v2"):
            add_expected(ctx.value("projects.jitsi.service.prosody%s.serve_port" % suffix))

        for domino_config in (ctx.value("projects.domino") or {}).values():
            if not isinstance(domino_config, dict):
                continue
            add_expected(domino_config.get("service", {}).get("manticore", {}).get("external_port"))
            add_expected(domino_config.get("go_database_controller_port"))
            add_expected(domino_config.get("go_database_controller_profiler_port"))

        add_expected(ctx.value("projects.jitsi.service.jvb.media_port"))

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
            elif ctx.values_loaded and published_port not in expected:
                unexpected.append("%d — сервис %s" % (published_port, name))

    if dangerous:
        ctx.record("security", "опубликованные порты", STATUS_FAIL,
                   "наружу опубликованы порты баз/админок (%d): %s — закройте публикацию в compose проекта" % (
                       len(dangerous), "; ".join(dangerous[:5])))
    elif unexpected:
        ctx.record("security", "опубликованные порты", STATUS_WARN,
                   "неожиданные порты (%d): %s — сверьте со списком ожидаемых из values" % (
                       len(unexpected), "; ".join(unexpected[:5])))
    else:
        ctx.record("security", "опубликованные порты", STATUS_OK,
                   "наружу смотрят только ожидаемые порты (%d)" % len(expected))


# получить PEM первого сертификата от сервера (без верификации)
def fetch_tls_chain(host, port):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=args.http_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                protocol = tls_sock.version() or "?"
                der_cert = tls_sock.getpeercert(binary_form=True)
    except Exception as e:
        return None, None, str(e)

    if not der_cert:
        return None, protocol, "сервер не отдал сертификат"

    return ssl.DER_cert_to_PEM_cert(der_cert), protocol, None


@check("security", "SSL-цепочка")
def check_security_ssl_chain(ctx):
    if not ctx.values_loaded:
        ctx.record("security", "SSL-цепочка", STATUS_SKIP, "values не загружены")
        return

    host = ctx.value("host")
    port = int(ctx.value("projects.monolith.service.nginx.external_https_port") or 443)
    if not host or host == "example.com":
        ctx.record("security", "SSL-цепочка", STATUS_SKIP, "host в values не задан (%r)" % host)
        return

    pem, protocol, error_text = fetch_tls_chain(host, port)
    if error_text:
        ctx.record("security", "SSL-цепочка", STATUS_SKIP,
                   "не удалось подключиться к %s:%d: %s (проверка пропущена)" % (host, port, error_text[:150]))
        return

    # subject/issuer листового сертификата
    rc, out, _ = run_cmd(["openssl", "x509", "-noout", "-subject", "-issuer"],
                         timeout=15, input_bytes=pem.encode("utf-8"))
    subject_cn = re.search(r"CN\s*=\s*([^,/]+)", out)
    issuer_cn = re.search(r"issuer=.*?CN\s*=\s*([^,/]+)", out)
    subject_name = subject_cn.group(1).strip() if subject_cn else "?"
    issuer_name = issuer_cn.group(1).strip() if issuer_cn else "?"

    if subject_name == issuer_name:
        ctx.record("security", "SSL-цепочка", STATUS_WARN,
                   "%s:%d — сертификат self-signed (CN=%s); проверка цепочки неприменима, "
                   "клиенты должны доверять корневому CA (TLS %s)" % (host, port, subject_name, protocol))
        return

    # не self-signed — проверяем полноту цепочки через openssl s_client
    rc, out, err = run_cmd(
        ["openssl", "s_client", "-connect", "%s:%d" % (host, port), "-servername", host, "-showcerts"],
        timeout=30, input_bytes=b"")
    chain_length = out.count("BEGIN CERTIFICATE")
    verify_ok = ": ok" in out
    verify_error = re.search(r"verify error:([^\n]+)", out)

    if chain_length >= 2 and verify_ok:
        ctx.record("security", "SSL-цепочка", STATUS_OK,
                   "%s:%d — цепочка из %d сертификатов, verify ok (TLS %s)" % (host, port, chain_length, protocol))
    elif verify_error:
        ctx.record("security", "SSL-цепочка", STATUS_FAIL,
                   "%s:%d — %s; цепочка: %d серт. — соберите fullchain (листовой + промежуточные) "
                   "и переустановите сертификат" % (host, port, verify_error.group(1).strip(), chain_length))
    elif chain_length < 2:
        ctx.record("security", "SSL-цепочка", STATUS_WARN,
                   "%s:%d — сервер отдал только листовой сертификат (CN=%s, issuer=%s); часть клиентов "
                   "(Android, библиотеки) не соберут цепочку — проверьте fullchain" % (
                       host, port, subject_name, issuer_name))
    else:
        ctx.record("security", "SSL-цепочка", STATUS_WARN,
                   "%s:%d — цепочка из %d серт., verify не ok; смотрите openssl s_client" % (
                       host, port, chain_length))


@check("security", "docker.sock")
def check_security_docker_sock(ctx):
    client = ctx.docker()
    if client is None:
        ctx.record("security", "docker.sock", STATUS_SKIP, "docker недоступен: %s" % ctx.docker_error)
        return

    mounted_containers = []
    try:
        for container in client.containers.list():
            try:
                mounts = container.attrs.get("Mounts") or []
                if any("docker.sock" in str(mount.get("Source", "")) for mount in mounts):
                    mounted_containers.append(container.name)
            except Exception:
                continue
    except Exception as e:
        ctx.record("security", "docker.sock", STATUS_SKIP, "не удалось получить контейнеры: %s" % e)
        return

    if not mounted_containers:
        ctx.record("security", "docker.sock", STATUS_OK, "не смонтирован ни в один контейнер")
        return

    suspicious = [name for name in mounted_containers
                  if not any(prefix in name for prefix in DOCKER_SOCK_LEGITIMATE)]
    if suspicious:
        ctx.record("security", "docker.sock", STATUS_WARN,
                   "смонтирован в контейнеры (%d): %s — доступ к сокету = root на хосте; "
                   "убедитесь, что это осознанно" % (
                       len(mounted_containers), "; ".join(suspicious[:5])))
    else:
        ctx.record("security", "docker.sock", STATUS_OK,
                   "смонтирован только в ожидаемые сервисы (%d)" % len(mounted_containers))


# ---ПРОВЕРКИ: БАЗЫ ДАННЫХ---#

# найти контейнеры стека по подстроке имени
def find_containers(ctx, stack, name_substring):
    return [
        container for container in ctx.stack_containers(stack)
        if name_substring in container.name
    ]


# ---ПРОВЕРКИ: ТРЕБОВАНИЯ К СЕРВЕРУ---#

# минимальные требования из документации (doc-onpremise.getcompass.ru/requirements.html)
MIN_REQUIRED_CPU = 12
MIN_REQUIRED_RAM_GB = 20
MIN_REQUIRED_DISK_GB = 200


@check("requirements", "CPU/RAM/диск (мин. требования)")
def check_requirements_resources(ctx):
    problems = []
    notes = []

    cpu_count = os.cpu_count() or 0
    if cpu_count and cpu_count < MIN_REQUIRED_CPU:
        problems.append("CPU %d ядер < %d" % (cpu_count, MIN_REQUIRED_CPU))

    try:
        with open("/proc/meminfo") as meminfo_file:
            for line in meminfo_file:
                if line.startswith("MemTotal:"):
                    ram_gb = int(line.split()[1]) / 1024 ** 2
                    if ram_gb < MIN_REQUIRED_RAM_GB:
                        problems.append("RAM %.0f ГБ < %d ГБ" % (ram_gb, MIN_REQUIRED_RAM_GB))
                    break
    except OSError:
        notes.append("размер памяти не определился (/proc/meminfo недоступен)")

    root_mount_path = ctx.value("root_mount_path")
    if root_mount_path and Path(root_mount_path).exists():
        rc, out, _ = run_cmd(["df", "-BG", "-P", root_mount_path], timeout=30)
        if rc == 0:
            fields = out.splitlines()[-1].split()
            if len(fields) >= 2:
                try:
                    disk_gb = int(fields[1].rstrip("G"))
                    if disk_gb < MIN_REQUIRED_DISK_GB:
                        problems.append("диск %s: %d ГБ < %d ГБ" % (root_mount_path, disk_gb, MIN_REQUIRED_DISK_GB))
                except ValueError:
                    notes.append("размер диска не распарсился: %s" % fields[1])
    else:
        notes.append("root_mount_path неизвестен или не существует")

    if problems:
        ctx.record("requirements", "CPU/RAM/диск (мин. требования)", STATUS_WARN,
                   "%s — сервисы (особенно php_monolith) могут не подняться или работать нестабильно; "
                   "тестовые стенды могут быть меньше намеренно. "
                   "Заодно замерьте диск: fio --name=t --filename=/tmp/fio --size=1G --rw=randread --bs=4k --direct=1 "
                   "(нужно ~1200 случайных IOPS на чтение)" % "; ".join(problems))
        return

    ctx.record("requirements", "CPU/RAM/диск (мин. требования)", STATUS_OK,
               "CPU %s, %s%s" % (
                   cpu_count or "?",
                   "требованиям соответствует",
                   ("; %s" % "; ".join(notes)) if notes else "",
               ))


@check("requirements", "порты входящих соединений")
def check_requirements_ports(ctx):
    if not ctx.values_loaded:
        ctx.record("requirements", "порты входящих соединений", STATUS_SKIP, "values не загружены")
        return

    # ожидаемые слушающие порты собираем из values
    expected_tcp = []

    def add_tcp(port, description):
        if port:
            try:
                expected_tcp.append((int(port), description))
            except (TypeError, ValueError):
                pass

    add_tcp(ctx.value("projects.monolith.service.nginx.external_https_port"), "главный nginx")
    add_tcp(ctx.value("projects.monolith.service.nginx.external_http_port"), "главный nginx (http)")

    gateway_id = ctx.value("api_gateway_id", "gateway-1")
    add_tcp(ctx.value("projects.api_gateway.%s.service.go_api_gateway.external_https_port" % gateway_id),
            "api_gateway")

    add_tcp(ctx.value("projects.auth.service.go_auth.external_grpc_port"), "go-auth grpc")
    add_tcp(ctx.value("projects.join_web.service.join_web.external_port"), "join_web")
    add_tcp(ctx.value("projects.jitsi_web.service.jitsi_web.external_port"), "jitsi_web")
    if ctx.value("projects.outlook_add_in.is_enabled"):
        add_tcp(ctx.value("projects.outlook_add_in.service.external_port"), "outlook_add_in")
    if ctx.value("siem.enabled_driver") == "kafka":
        add_tcp(ctx.value("projects.kafka.service.kafka.external_port"), "kafka")

    for domino_config in (ctx.value("projects.domino", {}) or {}).values():
        if not isinstance(domino_config, dict):
            continue
        add_tcp(domino_config.get("service", {}).get("manticore", {}).get("external_port"),
                "manticore (поиск)")
        add_tcp(domino_config.get("go_database_controller_port"), "go-database-controller")

    expected_udp = []
    turn_note = ""
    jvb_media_port = ctx.value("projects.jitsi.service.jvb.media_port")
    if jvb_media_port:
        expected_udp.append((int(jvb_media_port), "медиа-трафик звонков (jvb)"))

    # TURN: внешний сервер getCompass проверять локально не нужно — только свой
    turn_host = ctx.value("projects.jitsi.service.turn.host")
    turn_is_local = False
    if turn_host:
        try:
            turn_is_local = any(
                addr[4][0] in (socket.gethostbyname_ex(turn_host)[2] or [""])
                for addr in socket.getaddrinfo(socket.gethostname(), None)
            ) or turn_host in ("localhost", "127.0.0.1")
        except Exception:
            turn_is_local = False
    if turn_host and turn_is_local:
        expected_udp.append((3478, "TURN-сервер"))
    elif turn_host:
        turn_note = "TURN внешний (%s) — локально не проверяем" % turn_host

    # фактические слушающие порты
    def listening_ports(protocol_flag):
        rc, out, _ = run_cmd(["ss", "-%sn" % protocol_flag], timeout=30)
        if rc != 0:
            return None
        ports = set()
        for line in out.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]
            try:
                ports.add(int(local.rsplit(":", 1)[1]))
            except (IndexError, ValueError):
                continue
        return ports

    tcp_ports = listening_ports("tl")
    udp_ports = listening_ports("ul")
    if tcp_ports is None:
        ctx.record("requirements", "порты входящих соединений", STATUS_SKIP,
                   "не удалось получить список портов (ss отсутствует?)")
        return

    missing = []
    for port, description in expected_tcp:
        if port not in tcp_ports:
            missing.append("%d/tcp (%s)" % (port, description))
    for port, description in expected_udp:
        if udp_ports is None or port not in udp_ports:
            missing.append("%d/udp (%s)" % (port, description))

    if missing:
        ctx.record("requirements", "порты входящих соединений", STATUS_WARN,
                   "не слушаются: %s — сервис не запущен или порт не опубликован "
                   "(клиентский firewall проверяйте отдельно)" % ", ".join(missing))
        return

    total = len(expected_tcp) + len(expected_udp)
    ctx.record("requirements", "порты входящих соединений", STATUS_OK,
               "все ожидаемые порты (%d) слушаются%s" % (total, ("; %s" % turn_note) if turn_note else ""))


# ---ПРОВЕРКИ: ВНЕШНИЕ ЗАВИСИМОСТИ---#

# проверка доступности внешнего http-сервиса с валидацией TLS
# (для getcompass-сервисов сертификаты публичные — ловим и подмену прокси, и отсутствие CA)
def external_http_check(ctx, name, url):
    proxy_note = ""
    proxy_host = ctx.value("proxy.host")
    proxy_port = ctx.value("proxy.port") or 0
    if proxy_host and proxy_host not in ("0.0.0.0", "") and int(proxy_port or 0) > 0:
        proxy_note = " (в values настроен прокси %s:%s — проверяйте доступ через него)" % (proxy_host, proxy_port)

    try:
        response = requests.get(url, verify=True, timeout=args.http_timeout, allow_redirects=True)
        ctx.record("external", name, STATUS_OK, "%s — доступен, код %d%s" % (
            url, response.status_code, proxy_note))
        return
    except requests.exceptions.SSLError as e:
        ctx.record("external", name, STATUS_FAIL,
                   "%s — TLS-ошибка: %s%s — вероятно, трафик перехватывается (прозрачный прокси) "
                   "или в системе нет корневых сертификатов" % (url, error_summary(str(e)), proxy_note))
        return
    except Exception as e:
        ctx.record("external", name, STATUS_FAIL, "%s — недоступен: %s%s (исходящий 443/tcp, DNS)" % (
            url, error_summary(str(e)), proxy_note))


@check("external", "license.getcompass.ru")
def check_external_license(ctx):
    external_http_check(ctx, "license.getcompass.ru", "https://license.getcompass.ru/")


@check("external", "push-сервер getCompass")
def check_external_push(ctx):
    external_http_check(ctx, "push-сервер getCompass", "https://push-onpremise.getcompass.ru/")


@check("external", "docker registry")
def check_external_registry(ctx):
    external_http_check(ctx, "docker registry", "https://docker.getcompass.ru/v2/")


@check("external", "billing-домен")
def check_external_billing(ctx):
    if not ctx.values_loaded:
        ctx.record("external", "billing-домен", STATUS_SKIP, "values не загружены")
        return

    billing_domain = ctx.value("billing_domain")
    if not billing_domain or "example.com" in billing_domain:
        ctx.record("external", "billing-домен", STATUS_SKIP,
                   "billing_domain не задан (%r) — биллинг не используется" % billing_domain)
        return

    external_http_check(ctx, "billing-домен", "https://%s/" % billing_domain)


@check("external", "SMTP (исходящая почта)")
def check_external_smtp(ctx):
    # настройки почты живут в configs/auth.yaml инсталлятора (не в values)
    auth_path = Path(ctx.installer_dir) / "configs" / "auth.yaml"
    if not auth_path.exists():
        ctx.record("external", "SMTP (исходящая почта)", STATUS_SKIP,
                   "не найден %s — почта не настроена (коды/письма не отправляются)" % auth_path)
        return

    try:
        import yaml as yaml_module

        auth_config = yaml_module.safe_load(auth_path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        ctx.record("external", "SMTP (исходящая почта)", STATUS_WARN,
                   "не удалось прочитать configs/auth.yaml: %s" % e)
        return

    # ключи зовутся по-разному в разных версиях — собираем щедро
    def find_auth_value(*keys):
        for key in keys:
            for source in (auth_config, auth_config.get("mail") or {}, auth_config.get("smtp") or {}):
                if isinstance(source, dict) and source.get(key):
                    return source[key]
        return None

    smtp_host = find_auth_value("host", "smtp_host", "server", "smtp_server")
    smtp_port = find_auth_value("port", "smtp_port", "secure_port")
    if not smtp_host:
        # метод mail включён, а SMTP не настроен — коды подтверждения не уйдут
        available_methods = auth_config.get("available_methods") or []
        if "mail" in available_methods:
            ctx.record("external", "SMTP (исходящая почта)", STATUS_WARN,
                       "available_methods содержит mail, но smtp-хост в configs/auth.yaml не задан — "
                       "коды подтверждения отправляться не будут")
        else:
            ctx.record("external", "SMTP (исходящая почта)", STATUS_SKIP,
                       "в configs/auth.yaml не найден smtp-хост — почта не настроена")
        return

    smtp_port = int(smtp_port or 587)
    try:
        with socket.create_connection((str(smtp_host), smtp_port), timeout=args.http_timeout):
            ctx.record("external", "SMTP (исходящая почта)", STATUS_OK,
                       "%s:%d — доступен" % (smtp_host, smtp_port))
    except Exception as e:
        ctx.record("external", "SMTP (исходящая почта)", STATUS_FAIL,
                   "%s:%d — недоступен: %s (firewall/DNS или неверные настройки)" % (
                       smtp_host, smtp_port, error_summary(str(e))))


@check("external", "время сервера")
def check_server_time(ctx):
    # рассинхрон времени ломает jwt/sso-авторизацию; сверяемся с Date внешнего сервера
    try:
        response = requests.get("https://license.getcompass.ru/", timeout=args.http_timeout, verify=False)
    except Exception as e:
        ctx.record("external", "время сервера", STATUS_SKIP, "нет доступа к внешнему серверу для сверки: %s" % str(e)[:120])
        return

    date_header = response.headers.get("Date", "")
    if not date_header:
        ctx.record("external", "время сервера", STATUS_SKIP, "внешний сервер не отдал Date")
        return

    try:
        remote_time = email.utils.parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        ctx.record("external", "время сервера", STATUS_SKIP, "не удалось разобрать Date: %r" % date_header)
        return

    drift_seconds = abs((datetime.now(timezone.utc) - remote_time).total_seconds())

    if drift_seconds > 1800:
        ctx.record("external", "время сервера", STATUS_FAIL,
                   "расхождение с внешним сервером %.0f сек — jwt/sso-авторизация будет ломаться; настройте синхронизацию времени (chrony/ntp)" % drift_seconds)
    elif drift_seconds > 120:
        ctx.record("external", "время сервера", STATUS_WARN,
                   "расхождение с внешним сервером %.0f сек — проверьте синхронизацию времени (chrony/ntp)" % drift_seconds)
    else:
        ctx.record("external", "время сервера", STATUS_OK, "расхождение %.0f сек" % drift_seconds)


# ---ПРОВЕРКИ: DNS (хост и контейнеры)---#

# имена, которые обязан резолвить хост: лицензия + собственный домен из values
def dns_probe_names(ctx):
    names = ["license.getcompass.ru"]
    host_value = ctx.value("host")
    if host_value and host_value != "example.com":
        names.append(host_value)
    return names


@check("external", "DNS с хоста")
def check_external_dns_host(ctx):
    # детект systemd-resolved stub: если все nameserver-ы локальные (127.*),
    # docker не сможет отдать их контейнерам и молча подставит публичный DNS
    stub_only = False
    try:
        resolv_text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
        nameservers = [line.split()[1] for line in resolv_text.splitlines()
                       if line.strip().startswith("nameserver")]
        stub_only = bool(nameservers) and all(ns.startswith("127.") for ns in nameservers)
    except OSError:
        pass

    resolved, failed = [], []
    for name in dns_probe_names(ctx):
        try:
            addr_infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
            ips = sorted({info[4][0] for info in addr_infos})
            resolved.append("%s -> %s" % (name, ", ".join(ips[:2])))
        except socket.gaierror as e:
            failed.append("%s (%s)" % (name, error_summary(str(e))))

    if failed:
        ctx.record("external", "DNS с хоста", STATUS_FAIL,
                   "не резолвятся: %s — проверьте DNS-серверы в /etc/resolv.conf" % ", ".join(failed))
        return

    if stub_only:
        ctx.record("external", "DNS с хоста", STATUS_WARN,
                   "%s; но в /etc/resolv.conf только stub-резолвер (127.0.0.53): контейнерам docker "
                   "подставит публичный DNS — убедитесь, что исходящий UDP 53 открыт, или пропишите "
                   "рабочие dns в /etc/docker/daemon.json" % "; ".join(resolved))
        return

    ctx.record("external", "DNS с хоста", STATUS_OK, "; ".join(resolved))


@check("external", "DNS из контейнера")
def check_external_dns_container(ctx):
    # берём живой контейнер приложения (php-monolith или любой php/go на этой ноде)
    probe_container = None
    for stack in ctx.stacks():
        for name_substring in ("php-monolith", "php-file-node", "go-sender"):
            found = find_containers(ctx, stack, name_substring)
            if found:
                probe_container = found[0]
                break
        if probe_container is not None:
            break

    if probe_container is None:
        ctx.record("external", "DNS из контейнера", STATUS_SKIP,
                   "нет подходящего контейнера на этой ноде")
        return

    monolith_label = ctx.value("projects.monolith.label", "monolith")
    external_name = "license.getcompass.ru"
    internal_name = "mysql-%s" % monolith_label

    def resolve_in_container(name):
        rc, out = exec_in_container(probe_container, "getent hosts %s" % name)
        if rc != 0 and "not found" in out.lower():
            return None, out  # в образе нет getent
        resolved = rc == 0 and bool(out.strip())
        return resolved, (out.splitlines()[0].strip() if out.strip() else "")

    getent_missing = None
    external_ok, external_out = resolve_in_container(external_name)
    if external_ok is None:
        getent_missing = external_out
        ctx.record("external", "DNS из контейнера", STATUS_SKIP,
                   "в образе %s нет getent — проверка пропущена" % probe_container.name.split(".")[0][:40])
        return

    internal_ok, internal_out = resolve_in_container(internal_name)

    container_short = probe_container.name.split(".")[0][:50]
    if external_ok and internal_ok:
        external_ip = external_out.split()[0] if external_out.split() else external_name
        ctx.record("external", "DNS из контейнера", STATUS_OK,
                   "из %s: %s -> %s; внутренние имена тоже ок (%s)" % (
                       container_short, external_name, external_ip, internal_name))
        return

    if internal_ok and not external_ok:
        ctx.record("external", "DNS из контейнера", STATUS_FAIL,
                   "из %s внешние имена не резолвятся (%s), внутренние ок — внешний DNS контейнеров недоступен. "
                   "Смотреть: journalctl -u docker | grep 'failed to query external DNS'; лечение: рабочие dns "
                   "в /etc/docker/daemon.json + systemctl restart docker (в окно обслуживания), "
                   "если исходящий 53 закрыт — DNS клиента вместо публичных" % (container_short, external_name))
        return

    if not internal_ok and not external_ok:
        ctx.record("external", "DNS из контейнера", STATUS_FAIL,
                   "из %s не резолвится ничего (даже внутреннее %s) — проблема сети контейнера/overlay, "
                   "не только DNS" % (container_short, internal_name))
        return

    ctx.record("external", "DNS из контейнера", STATUS_WARN,
               "из %s внешние ок, но внутреннее %s не резолвится — проверьте, что сервисы в одной сети" % (
                   container_short, internal_name))


# ---ПРОВЕРКИ: ФУНКЦИОНАЛЬНЫЕ СМОУК-ТЕСТЫ---#

@check("functional", "автоудаление файлов: очередь")
def check_functional_file_queue(ctx):
    if not ctx.values_loaded:
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_SKIP, "values не загружены")
        return

    auto_deletion = ctx.value("file_auto_deletion", {}) or {}
    if not auto_deletion.get("is_enabled"):
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_SKIP,
                   "автоудаление отключено (file_auto_deletion.is_enabled=0)")
        return

    file_ttl = auto_deletion.get("file_ttl")
    try:
        file_ttl_days = int(file_ttl)
    except (TypeError, ValueError):
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_SKIP,
                   "file_ttl не задан — ttl-очередь не считается")
        return

    monolith_label = ctx.value("projects.monolith.label", "monolith")
    containers = []
    for stack in ctx.stacks():
        if stack.endswith("-%s" % monolith_label):
            containers = find_containers(ctx, stack, "mysql-%s" % monolith_label)
            break

    if not containers:
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_SKIP,
                   "не найден контейнер mysql монолита на этой ноде")
        return

    sql = ("SELECT COUNT(*) FROM `file_node`.`file` "
           "WHERE is_deleted=0 AND last_access_at < DATE_SUB(NOW(), INTERVAL %d DAY)" % file_ttl_days)
    ok, out = mysql_query(ctx, containers[0], sql)
    if not ok:
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_SKIP,
                   "запрос не выполнился (таблица file_node.file отсутствует?): %s" % first_line(out))
        return

    try:
        queue_size = int(re.search(r"\d+", out.splitlines()[-1]).group(0))
    except (AttributeError, ValueError, IndexError):
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_SKIP,
                   "не удалось разобрать ответ: %s" % first_line(out))
        return

    if queue_size >= 50000:
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_FAIL,
                   "%d просроченных файлов — критично: пакетное удаление упадёт по OOM "
                   "(exit 255), удаляйте порциями (см. базу знаний: file-node-exit-255-oom)" % queue_size)
    elif queue_size >= 1000:
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_WARN,
                   "%d просроченных файлов — следите за размером, большие пачки опасны (OOM)" % queue_size)
    else:
        ctx.record("functional", "автоудаление файлов: очередь", STATUS_OK,
                   "%d просроченных файлов (ttl=%d дн.)" % (queue_size, file_ttl_days))


@check("functional", "крон автоудаления в file-node")
def check_functional_file_cron(ctx):
    # при выключенном автоудалении задачи в кроне и не должно быть
    auto_deletion = ctx.value("file_auto_deletion", {}) or {}
    if ctx.values_loaded and not auto_deletion.get("is_enabled"):
        ctx.record("functional", "крон автоудаления в file-node", STATUS_SKIP,
                   "автоудаление отключено (file_auto_deletion.is_enabled=0) — задачи в кроне не ожидается")
        return

    file_node_containers = []
    for stack in ctx.stacks():
        file_node_containers = find_containers(ctx, stack, "php-file-node")
        if file_node_containers:
            break

    if not file_node_containers:
        ctx.record("functional", "крон автоудаления в file-node", STATUS_SKIP,
                   "не найден контейнер php-file-node на этой ноде")
        return

    container = file_node_containers[0]

    # смонтированный crontab (docker config file-node-crontab)
    rc, mounted = exec_in_container(
        container, "cat /app/src/Compass/FileNode/sh/cron/crontab.cron 2>/dev/null")
    mounted_has_job = rc == 0 and "delete_expired_files" in mounted

    # активный crontab пользователя внутри контейнера
    rc, active = exec_in_container(container, "crontab -l 2>/dev/null")
    active_has_job = rc == 0 and "delete_expired_files" in active

    if mounted_has_job and active_has_job:
        ctx.record("functional", "крон автоудаления в file-node", STATUS_OK,
                   "задача delete_expired_files в кронтабе (смонтирован и активен)")
    elif mounted_has_job and not active_has_job:
        ctx.record("functional", "крон автоудаления в file-node", STATUS_WARN,
                   "конфиг крона смонтирован, но в активном crontab -l задачи нет — "
                   "cron может не работать (проверьте процесс cron в контейнере)")
    elif not mounted_has_job:
        ctx.record("functional", "крон автоудаления в file-node", STATUS_FAIL,
                   "в /app/src/Compass/FileNode/sh/cron/crontab.cron нет delete_expired_files — "
                   "автоудаление файлов не запланировано")
    else:
        ctx.record("functional", "крон автоудаления в file-node", STATUS_OK,
                   "задача в активном crontab есть")


@check("functional", "manticore: живость поиска")
def check_functional_manticore(ctx):
    manticore_containers = []
    for stack in ctx.stacks():
        manticore_containers = find_containers(ctx, stack, "manticore")
        if manticore_containers:
            break

    if not manticore_containers:
        ctx.record("functional", "manticore: живость поиска", STATUS_SKIP,
                   "не найден контейнер manticore на этой ноде")
        return

    container = manticore_containers[0]
    rc, out = exec_in_container(
        container, "mysql -h127.0.0.1 -P9306 --connect-timeout=5 -e 'SHOW STATUS LIKE %suptime%s' 2>&1" % ("'", "'"))

    if rc == 0 and "uptime" in out.lower():
        uptime_line = [line for line in out.splitlines() if "uptime" in line.lower()]
        ctx.record("functional", "manticore: живость поиска", STATUS_OK,
                   "searchd отвечает: %s" % (uptime_line[0].strip() if uptime_line else "ok"))
        return

    if "not found" in out.lower() or "command not found" in out.lower():
        ctx.record("functional", "manticore: живость поиска", STATUS_SKIP,
                   "в образе manticore нет mysql-клиента — проверка через порт есть в группе db")
        return

    ctx.record("functional", "manticore: живость поиска", STATUS_FAIL,
               "searchd не отвечает на запрос: %s" % first_line(out))


@check("db", "mysql монолита")
def check_db_monolith(ctx):
    monolith_label = ctx.value("projects.monolith.label", "monolith")
    stack = "%s-%s" % (ctx.stack_prefix, monolith_label)

    if stack not in ctx.stacks():
        ctx.record("db", "mysql монолита", STATUS_SKIP, "стек %s не найден" % stack)
        return

    containers = find_containers(ctx, stack, "mysql-%s" % monolith_label)
    # отсекаем company-mysql, если вдруг попал
    containers = [c for c in containers if "company_mysql" not in c.name]

    if not containers:
        if ctx.value("database_connection.driver", "docker") != "docker":
            ctx.record("db", "mysql монолита", STATUS_SKIP, "внешняя база (database_connection.driver != docker)")
            return
        ctx.record("db", "mysql монолита", STATUS_FAIL,
                   "контейнер mysql не найден на этой ноде (запущен на другой ноде или упал)")
        return

    container = containers[0]
    ok, out = mysql_query(ctx, container, "SELECT 1 AS alive")
    if not ok:
        ctx.record("db", "mysql монолита", STATUS_FAIL, "SELECT 1: %s" % out[:300])
        return

    # ключевые базы
    ok, out = mysql_query(ctx, container, "SHOW DATABASES")
    databases = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith("+")]
    expected_databases = ["pivot_system", "company_system"]
    missing = [db_name for db_name in expected_databases if db_name not in databases]

    # контекст сервера: версия, аптайм, число подключений
    context_parts = []
    ok_ver, out_ver = mysql_query(ctx, container, "SELECT VERSION()")
    if ok_ver:
        version_lines = [line.strip() for line in out_ver.splitlines() if line.strip() and not line.startswith("+")]
        if version_lines:
            context_parts.append("MySQL %s" % version_lines[-1])
    ok_st, out_st = mysql_query(ctx, container,
                                "SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected')")
    if ok_st:
        uptime = re.search(r"Uptime\s+\|\s*(\d+)", out_st)
        threads = re.search(r"Threads_connected\s+\|\s*(\d+)", out_st)
        if uptime:
            days, hours = divmod(int(uptime.group(1)) // 3600, 24)
            context_parts.append("uptime %dд %dч" % (days, hours))
        if threads:
            context_parts.append("потоков: %s" % threads.group(1))
    context_text = " (%s)" % ", ".join(context_parts) if context_parts else ""

    if missing:
        ctx.record("db", "mysql монолита", STATUS_WARN,
                   "подключение ок, но нет баз: %s (всего баз: %d)%s" % (
                       ", ".join(missing), len(databases), context_text))
        return

    ctx.record("db", "mysql монолита", STATUS_OK, "подключение ок, базы %s на месте (%d баз)%s" % (
        ", ".join(expected_databases), len(databases), context_text))


@check("db", "mysql команд (company)")
def check_db_company(ctx):
    domino_projects = ctx.value("projects.domino", {}) or {}
    if not isinstance(domino_projects, dict) or not domino_projects:
        ctx.record("db", "mysql команд (company)", STATUS_SKIP, "домино в values не настроены")
        return

    checked_any = False
    for domino_config in domino_projects.values():
        label = (domino_config or {}).get("label")
        if not label:
            continue

        stack = "%s-%s-company" % (ctx.stack_prefix, label)
        if stack not in ctx.stacks():
            continue

        checked_any = True
        containers = find_containers(ctx, stack, "company_mysql")
        if not containers:
            ctx.record("db", "mysql компании %s" % label, STATUS_FAIL,
                       "контейнер company_mysql не найден на этой ноде")
            continue

        ok, out = mysql_query(ctx, containers[0], "SELECT 1 AS alive")
        if ok:
            ctx.record("db", "mysql компании %s" % label, STATUS_OK, "подключение ок")
        else:
            ctx.record("db", "mysql компании %s" % label, STATUS_FAIL, "SELECT 1: %s" % out[:300])

    if not checked_any:
        ctx.record("db", "mysql команд (company)", STATUS_SKIP, "стеки компаний не найдены")


@check("db", "репликация mysql")
def check_db_replication(ctx):
    # включена ли репликация, без assert'ов scriptutils (там die на Yandex Cloud)
    service_label = ctx.value("service_label")
    if not service_label:
        ctx.record("db", "репликация mysql", STATUS_SKIP, "репликация не настроена (service_label пуст)")
        return

    master_label = ctx.value("master_service_label")
    if master_label and service_label != master_label:
        # мы реплика — проверяем статус ведомого
        monolith_stack = "%s-%s" % (ctx.stack_prefix, ctx.value("projects.monolith.label", "monolith"))
        containers = find_containers(ctx, monolith_stack, "mysql")
        containers = [c for c in containers if "company_mysql" not in c.name]
        if not containers:
            ctx.record("db", "репликация mysql", STATUS_FAIL, "не найден mysql-контейнер на реплике")
            return

        ok, out = mysql_query(ctx, containers[0], "SHOW SLAVE STATUS\\G")
        if not ok:
            ctx.record("db", "репликация mysql", STATUS_FAIL, "SHOW SLAVE STATUS: %s" % out[:300])
            return

        io_running = re.search(r"Slave_IO_Running:\s*(\w+)", out)
        sql_running = re.search(r"Slave_SQL_Running:\s*(\w+)", out)
        seconds_behind = re.search(r"Seconds_Behind_Master:\s*(\d+)", out)

        if not io_running or not sql_running:
            ctx.record("db", "репликация mysql", STATUS_WARN, "не удалось разобрать SHOW SLAVE STATUS")
            return

        if io_running.group(1) != "Yes" or sql_running.group(1) != "Yes":
            last_error = re.search(r"Last_(?:IO|SQL)_Error:\s*(.+)", out)
            ctx.record("db", "репликация mysql", STATUS_FAIL,
                       "репликация стоит (IO=%s, SQL=%s) %s" % (
                           io_running.group(1), sql_running.group(1),
                           last_error.group(1).strip()[:200] if last_error else "",
                       ))
            return

        lag = int(seconds_behind.group(1)) if seconds_behind else -1
        if lag > 300:
            ctx.record("db", "репликация mysql", STATUS_WARN, "репликация идёт, отставание %d сек." % lag)
        else:
            ctx.record("db", "репликация mysql", STATUS_OK, "репликация идёт, отставание %d сек." % lag)
    else:
        ctx.record("db", "репликация mysql", STATUS_SKIP,
                   "это мастер-сервер (%s) — статус реплики проверяется на ведомом" % service_label)


@check("db", "manticore (поиск)")
def check_manticore(ctx):
    if not ctx.values_loaded:
        ctx.record("db", "manticore (поиск)", STATUS_SKIP, "values не загружены")
        return

    domino_projects = ctx.value("projects.domino", {}) or {}
    for domino_id, domino_config in (domino_projects.items() if isinstance(domino_projects, dict) else []):
        label = (domino_config or {}).get("label")
        external_port = ((domino_config or {}).get("service", {}) or {}).get("manticore", {}).get("external_port")
        if not label or not external_port:
            continue

        # manticore публикует mysql-протокол на внешний порт — проверяем TCP-соединение
        try:
            with socket.create_connection(("127.0.0.1", int(external_port)), timeout=10):
                ctx.record("db", "manticore %s" % label, STATUS_OK, "порт %d отвечает" % int(external_port))
        except Exception as e:
            ctx.record("db", "manticore %s" % label, STATUS_FAIL,
                       "порт %d не отвечает: %s" % (int(external_port), e))


# ---ПРОВЕРКИ: KAFKA---#

@check("kafka", "топики kafka")
def check_kafka_topics(ctx):
    if ctx.value("siem.enabled_driver") != "kafka":
        ctx.record("kafka", "топики kafka", STATUS_SKIP, "siem.enabled_driver != kafka")
        return

    monolith_stack = "%s-%s" % (ctx.stack_prefix, ctx.value("projects.monolith.label", "monolith"))
    containers = find_containers(ctx, monolith_stack, "kafka")
    if not containers:
        ctx.record("kafka", "топики kafka", STATUS_FAIL, "контейнер kafka не найден на этой ноде")
        return

    # пробуем утилиту в разных местах образа
    shell_cmd = (
        "kafka-topics --bootstrap-server localhost:9092 --command-config /etc/kafka/client.properties --list 2>/dev/null "
        "|| /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --command-config /etc/kafka/client.properties --list 2>/dev/null "
        "|| echo DIAG_KAFKA_UNAVAILABLE"
    )
    rc, out = exec_in_container(containers[0], shell_cmd, timeout=60)
    out = out.strip()

    if "DIAG_KAFKA_UNAVAILABLE" in out or rc != 0:
        ctx.record("kafka", "топики kafka", STATUS_WARN,
                   "не удалось выполнить kafka-topics внутри контейнера (утилита недоступна)")
        return

    actual_topics = [line.strip() for line in out.splitlines() if line.strip()]
    expected_topics = list((ctx.value("projects.kafka.service.kafka.topics", {}) or {}).keys())

    missing = [topic for topic in expected_topics if topic not in actual_topics]
    if missing:
        ctx.record("kafka", "топики kafka", STATUS_FAIL, "нет топиков: %s" % ", ".join(missing))
    else:
        ctx.record("kafka", "топики kafka", STATUS_OK,
                   "все топики из values на месте (%d шт.)" % len(expected_topics))


# ---ПРОВЕРКИ: ЛОГИ---#

# отрезать служебный префикс docker ("<task>@<host>    | <сообщение>")
def strip_log_prefix(line):
    head, separator, tail = line.partition("|")
    if separator and "@" in head and tail.strip():
        return tail.strip()
    return line.strip()


@check("logs", "ошибки в логах сервисов")
def check_logs(ctx):
    kb_entries = load_errors_kb()

    # {short_name: {"found": [(pattern, count), ...], "samples": [line, ...], "total": N}}
    per_service = {}
    top_messages = {}   # нормализованное сообщение -> [count, raw_line]
    hour_hits = {}      # "HH" -> count (часы по таймстемпам строк-совпадений)
    all_lines_scanned = 0

    for stack in ctx.stacks():
        for service in ctx.stack_services(stack):
            name = service.get("Name", "?")
            short_name = short_service_name(ctx, stack, name)

            rc, out, err = run_cmd(
                ["docker", "service", "logs", "--since", args.since, "--tail", str(args.log_tail), name],
                timeout=90,
            )
            if rc != 0:
                continue  # логи могли ротироваться/сервис удалён — не шумим

            # счётчики паттернов по сервису + примеры строк
            found_counts = {}
            samples = []
            for line in out.splitlines():
                all_lines_scanned += 1
                matched = [pattern_name for pattern_name, pattern in LOG_ERROR_PATTERNS if pattern.search(line)]
                if not matched:
                    continue

                for pattern_name in matched:
                    found_counts[pattern_name] = found_counts.get(pattern_name, 0) + 1
                if len(samples) < LOG_SAMPLES_PER_SERVICE:
                    samples.append(strip_log_prefix(line)[:300])

                # самое частое сообщение: цифры -> N схлопываем
                clean_line = strip_log_prefix(line)[:300]
                key = re.sub(r"\d+", "N", clean_line)
                item = top_messages.setdefault(key, [0, clean_line])
                item[0] += 1

                # час строки (docker: "service.1.abc@2026-08-27T10:12:34...")
                hour_match = re.search(r"@\d{4}-\d{2}-\d{2}T(\d{2}):", line)
                if hour_match:
                    hour_hits[hour_match.group(1)] = hour_hits.get(hour_match.group(1), 0) + 1

            if not found_counts:
                continue

            found = sorted(found_counts.items(), key=lambda item: -item[1])
            total = sum(count for _, count in found)

            # сверка с базой известных проблем; одинаковые строки (цифры -> N)
            # схлопываем и матчим по одному представителю — повторы лишь увеличивают счётчик
            kb_hits = {}
            if kb_entries:
                first_raw = {}
                counts = {}
                for line in out.splitlines():
                    key = re.sub(r"\d+", "N", line)
                    counts[key] = counts.get(key, 0) + 1
                    if key not in first_raw:
                        first_raw[key] = line

                for key, raw_line in first_raw.items():
                    entry = match_error_kb(kb_entries, raw_line)
                    if entry is not None:
                        prev = kb_hits.get(entry["id"], (entry, 0))
                        kb_hits[entry["id"]] = (entry, prev[1] + counts[key])

            per_service[short_name] = {
                "found": found, "samples": samples, "total": total, "kb_hits": kb_hits,
            }

    if not per_service:
        ctx.record("logs", "ошибки в логах сервисов", STATUS_OK,
                   "за %s просмотрено %d строк — ошибок и известных проблем не найдено" % (
                       args.since, all_lines_scanned))
        return

    # записи по каждому сервису
    for short_name, item in per_service.items():
        # известные проблемы: crit из базы — сразу FAIL, с рецептом в сообщении
        known_parts = []
        has_known_crit = False
        for entry, count in sorted(item["kb_hits"].values(), key=lambda entry_count: -entry_count[1]):
            known_parts.append("%s ×%d" % (entry["title"], count))
            if entry["severity"] == "crit":
                has_known_crit = True

        top_kb = sorted(item["kb_hits"].values(), key=lambda entry_count: -entry_count[1])
        recipe = " — %s" % top_kb[0][0]["fix"][:200] if top_kb and top_kb[0][0]["fix"] else ""

        status = STATUS_FAIL if (item["total"] >= LOG_FAIL_COUNT or has_known_crit) else STATUS_WARN

        message_parts = ["%s ×%d" % (pattern_name, count) for pattern_name, count in item["found"]]
        if known_parts:
            message_parts.append("известная проблема: %s%s" % ("; ".join(known_parts[:2]), recipe))
        if item["samples"]:
            message_parts.append("пример: %s" % item["samples"][0])
        ctx.record("logs", short_name, status, ", ".join(message_parts))

    # сводный топ сервисов по ошибкам
    top_services = sorted(per_service.items(), key=lambda name_item: -name_item[1]["total"])[:5]
    worst_status = STATUS_FAIL if any(
        item["total"] >= LOG_FAIL_COUNT or any(entry["severity"] == "crit" for entry, _ in item["kb_hits"].values())
        for _, item in top_services
    ) else STATUS_WARN
    ctx.record("logs", "топ сервисов по ошибкам", worst_status, "; ".join(
        "%s ×%d" % (short_name, item["total"]) for short_name, item in top_services))

    # самое частое сообщение (нормализованное)
    if top_messages:
        top_message_count, top_message_raw = max(top_messages.values(), key=lambda item: item[0])
        ctx.record("logs", "самое частое сообщение", STATUS_WARN,
                   "×%d: %s" % (top_message_count, top_message_raw[:200]))

    # часы-пиков ошибок (если в логах есть таймстемпы docker)
    if hour_hits:
        peak_hours = sorted(hour_hits.items(), key=lambda hour_count: -hour_count[1])[:3]
        ctx.record("logs", "часы-пиков ошибок", STATUS_WARN, "; ".join(
            "%s:00 ×%d" % (hour, count) for hour, count in peak_hours))


# ---ПРОВЕРКИ: БЭКАПЫ---#

@check("backups", "свежесть бэкапов")
def check_backups(ctx):
    root_mount_path = ctx.value("root_mount_path")
    if not root_mount_path:
        ctx.record("backups", "свежесть бэкапов", STATUS_SKIP, "root_mount_path неизвестен (values не загружены)")
        return

    backups_dir = Path(root_mount_path) / "backups"
    if not backups_dir.is_dir():
        ctx.record("backups", "свежесть бэкапов", STATUS_WARN, "каталог %s не найден" % backups_dir)
        return

    backup_items = list(backups_dir.iterdir())
    if not backup_items:
        ctx.record("backups", "свежесть бэкапов", STATUS_WARN, "каталог бэкапов пуст")
        return

    newest_path = max(backup_items, key=lambda item: item.stat().st_mtime)
    age_hours = (datetime.now().timestamp() - newest_path.stat().st_mtime) / 3600

    if age_hours > BACKUP_FAIL_HOURS:
        status = STATUS_FAIL
    elif age_hours > BACKUP_WARN_HOURS:
        status = STATUS_WARN
    else:
        status = STATUS_OK

    rc, out, err = run_cmd(["du", "-sh", str(backups_dir)], timeout=120)
    size_text = out.split()[0] if rc == 0 and out else "?"

    ctx.record("backups", "свежесть бэкапов", status,
               "последний: %s (%.1f ч назад), всего занимает: %s" % (newest_path.name, age_hours, size_text))


# ---ВЫВОД ОТЧЁТА---#

# запустить одну проверку, перехватывая любые исключения
def run_check_safely(check_item, ctx):
    try:
        check_item["func"](ctx)
    except Exception:
        ctx.record(check_item["group"], check_item["name"], STATUS_FAIL,
                   "проверка упала с исключением:\n%s" % traceback.format_exc(limit=5))


# текстовый отчёт
def print_report(ctx):
    for group, group_title in GROUPS:
        group_results = [result for result in ctx.results if result["group"] == group]
        if not group_results:
            continue

        print_line("")
        print_line(blue(("── %s " % group_title).ljust(78, "─")))

        for result in group_results:
            line = "  %s %s" % (status_label(result["status"]), result["name"])
            if result["message"]:
                line += ": %s" % result["message"]
            print_line(line)

    # итоги
    counts = {STATUS_OK: 0, STATUS_WARN: 0, STATUS_FAIL: 0, STATUS_SKIP: 0}
    for result in ctx.results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    print_line("")
    print_line(blue(("── Итог ").ljust(78, "─")))
    summary_line = "  OK: %d   %s   %s   SKIP: %d" % (
        counts[STATUS_OK],
        warning("WARN: %d" % counts[STATUS_WARN]),
        error("FAIL: %d" % counts[STATUS_FAIL]),
        counts[STATUS_SKIP],
    )
    print_line(summary_line)

    # сначала FAIL, затем WARN; рецепты из базы знаний — если паттерн сработал на сообщение
    problems = [result for result in ctx.results if result["status"] in (STATUS_FAIL, STATUS_WARN)]
    problems.sort(key=lambda result: 0 if result["status"] == STATUS_FAIL else 1)

    if problems:
        kb_entries = load_errors_kb()
        print_line("")
        print_line("  Проблемы (%d):" % len(problems))
        for result in problems:
            marker = error("[FAIL]") if result["status"] == STATUS_FAIL else warning("[WARN]")
            message = result["message"] or ""
            # в сводке — только первая строка сообщения (полный текст и traceback — выше, в теле группы)
            first_line = message.splitlines()[0] if message else ""
            if first_line:
                print_line("   %s %s: %s" % (marker, result["name"], first_line))
            else:
                print_line("   %s %s" % (marker, result["name"]))

            # рецепт из базы известных проблем (по тексту сообщения проверки)
            if kb_entries:
                match_text = "%s %s" % (result["name"], message)
                kb_entry = match_error_kb(kb_entries, match_text)
                if kb_entry and kb_entry["fix"] and kb_entry["fix"][:80] not in message:
                    print_line(cyan("       что делать: %s" % kb_entry["fix"].strip()))


# json-отчёт
def build_json_report(ctx):
    counts = {STATUS_OK: 0, STATUS_WARN: 0, STATUS_FAIL: 0, STATUS_SKIP: 0}
    for result in ctx.results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    return json.dumps({
        "started_at": ctx.started_at.isoformat(),
        "host": get_hostname(),
        "environment": ctx.environment,
        "values": ctx.values_name,
        "stack_prefix": ctx.stack_prefix if ctx.values_loaded else None,
        "log_period": args.since,
        "summary": {
            "ok": counts[STATUS_OK],
            "warn": counts[STATUS_WARN],
            "fail": counts[STATUS_FAIL],
            "skip": counts[STATUS_SKIP],
        },
        "results": ctx.results,
    }, ensure_ascii=False, indent=2)


# ---ТОЧКА ВХОДА---#

def tools_revision():
    # git-коммит самих инструментов — чтобы по отчёту понимать, какой версией снят
    try:
        rc, out, _ = run_cmd(["git", "-C", str(Path(__file__).resolve().parent), "log", "--oneline", "-1"], timeout=10)
    except Exception:
        return ""
    if rc == 0 and out.strip():
        return out.strip()
    return ""


def main():
    ctx = DiagnoseContext()

    # values грузим первыми: без них часть проверок уйдёт в SKIP, но диагностика продолжится
    ctx.values_error = load_values(ctx)

    if not args.json:
        print_line("")
        print_line(blue("Диагностика Compass On-premise"))
        print_line("  Сервер:          %s" % get_hostname())
        print_line("  Инструменты:     %s" % (tools_revision() or "неизвестно (не из git)"))
        print_line("  Каталог:         %s" % ctx.installer_dir)
        print_line("  Окружение:       %s (values: %s)" % (ctx.environment, ctx.values_name))
        print_line("  Префикс стеков:  %s" % (ctx.stack_prefix if ctx.values_loaded else "неизвестен (values не загружены)"))
        print_line("  Период логов:    %s" % args.since)
        print_line("")

    only_groups = [group.strip() for group in args.only.split(",") if group.strip()]
    known_groups = [group[0] for group in GROUPS]
    unknown_groups = [group for group in only_groups if group not in known_groups]
    if unknown_groups:
        die("Неизвестные группы проверок: %s (доступны: %s)" % (
            ", ".join(unknown_groups), ", ".join(known_groups)))

    for check_item in CHECKS:
        if only_groups and check_item["group"] not in only_groups:
            continue
        run_check_safely(check_item, ctx)

    if args.json:
        print(build_json_report(ctx))
    else:
        print_report(ctx)
        print_line("")

    # код завершения: 1, если есть FAIL
    has_fail = any(result["status"] == STATUS_FAIL for result in ctx.results)
    sys.exit(1 if has_fail else 0)


if __name__ == "__main__":
    main()
