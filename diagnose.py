#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Диагностика работающего окружения Compass On-premise.
# Скрипт прогоняет независимые проверки (конфигурация, инфраструктура, сервисы swarm,
# HTTP-доступность, базы, kafka, логи, бэкапы) и не останавливается на исключениях:
# любая упавшая проверка помечается как FAIL, остальные продолжают выполняться.
#
# Часть набора инструментов tools/ — работает отдельно от репозитория инсталлятора.
# Креды для mysql резолвятся по цепочке: env контейнера -> Docker Secrets -> values
# (работает и на классической схеме, и на ветке с паролями в Docker Secrets).

import os
import re
import ssl
import json
import socket
import traceback
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
    ("OOM", re.compile(r"OOMKilled|Out of memory|oom-killer|Killed process \d+")),
    ("panic", re.compile(r"panic:")),
    ("NEW EXCEPTION", re.compile(r"NEW EXCEPTION")),
    ("MySQL server has gone away", re.compile(r"MySQL server has gone away")),
    ("Segmentation fault", re.compile(r"Segmentation fault")),
    ("exit 255", re.compile(r"exit(ed )?(with|status)? ?(code )?255\b")),
    ("connection refused", re.compile(r"Connection refused", re.IGNORECASE)),
]

# порядок и заголовки групп проверок
GROUPS = [
    ("config", "Конфигурация (сверка с values)"),
    ("infra", "Инфраструктура"),
    ("requirements", "Требования к серверу"),
    ("services", "Сервисы swarm"),
    ("http", "HTTP-доступность"),
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
    description="Диагностика установленного окружения Compass On-premise: конфигурация, сервисы, базы, HTTP, логи, бэкапы.",
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
parser.add_argument("--since", required=False, default="1h", type=str,
                    help="За какой период смотреть логи и упавшие задачи (формат docker: 1h, 30m, 24h)")
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

    mode = security_path.stat().st_mode & 0o777
    if mode & 0o077:
        ctx.record("config", "security.yaml", STATUS_WARN,
                   "права %s: файл с ключами читают все локальные пользователи "
                   "(инсталлер создаёт его так по умолчанию; рекомендуется chmod 600)" % oct(mode))
        return

    ctx.record("config", "security.yaml", STATUS_OK, "найден, права %s" % oct(mode))


@check("config", "версия инсталлятора")
def check_version_file(ctx):
    version_path = Path(ctx.installer_dir + "/.version")
    if not version_path.exists():
        ctx.record("config", "версия инсталлятора", STATUS_WARN,
                   "файл .version не найден — обновления через installer_migrations_up.py не отслеживаются")
        return

    ctx.record("config", "версия инсталлятора", STATUS_OK, version_path.read_text().strip())


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

        ctx.record("infra", "диск %s" % path, status,
                   "свободно %.1f%% (%.1f ГБ)" % (free_percent, free_gb))


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

    if missing:
        ctx.record("db", "mysql монолита", STATUS_WARN,
                   "подключение ок, но нет баз: %s (всего баз: %d)" % (", ".join(missing), len(databases)))
        return

    ctx.record("db", "mysql монолита", STATUS_OK, "подключение ок, базы %s на месте (%d баз)" % (
        ", ".join(expected_databases), len(databases)))


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

@check("logs", "ошибки в логах сервисов")
def check_logs(ctx):
    noisy = []
    kb_entries = load_errors_kb()

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

            found = []
            for pattern_name, pattern in LOG_ERROR_PATTERNS:
                count = len(pattern.findall(out))
                if count > 0:
                    found.append("%s×%d" % (pattern_name, count))

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

            if found or kb_hits:
                noisy.append((short_name, found, kb_hits))

    if not noisy:
        ctx.record("logs", "ошибки в логах сервисов", STATUS_OK,
                   "за %s критичных паттернов и известных проблем не найдено" % args.since)
        return

    for short_name, found, kb_hits in noisy:
        total = sum(int(re.search(r"×(\d+)$", item).group(1)) for item in found if re.search(r"×(\d+)$", item))

        # известные проблемы: crit из базы — сразу FAIL, с рецептом в сообщении
        known_parts = []
        has_known_crit = False
        for entry, count in sorted(kb_hits.values(), key=lambda item: -item[1]):
            known_parts.append("%s ×%d" % (entry["title"], count))
            if entry["severity"] == "crit":
                has_known_crit = True
        if known_parts:
            top_entry = sorted(kb_hits.values(), key=lambda item: -item[1])[0][0]
            recipe = " — %s" % top_entry["fix"][:200] if top_entry["fix"] else ""

        if total >= LOG_FAIL_COUNT or has_known_crit:
            status = STATUS_FAIL
        else:
            status = STATUS_WARN

        message_parts = list(found)
        if known_parts:
            message_parts.append("известная проблема: %s%s" % ("; ".join(known_parts[:2]), recipe))
        ctx.record("logs", short_name, status, ", ".join(message_parts))


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

    problems = [result for result in ctx.results if result["status"] in (STATUS_FAIL, STATUS_WARN)]
    if problems:
        print_line("")
        print_line("  Проблемы (%d):" % len(problems))
        for result in problems:
            marker = error("[FAIL]") if result["status"] == STATUS_FAIL else warning("[WARN]")
            message = (": %s" % result["message"]) if result["message"] else ""
            print_line("   %s %s%s" % (marker, result["name"], message.splitlines()[0] if message else ""))


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

def main():
    ctx = DiagnoseContext()

    # values грузим первыми: без них часть проверок уйдёт в SKIP, но диагностика продолжится
    ctx.values_error = load_values(ctx)

    if not args.json:
        print_line("")
        print_line(blue("Диагностика Compass On-premise"))
        print_line("  Сервер:          %s" % get_hostname())
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
