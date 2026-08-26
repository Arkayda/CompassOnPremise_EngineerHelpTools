#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Разбор информационного бандла collect_info.py: вскрывает tar.gz (или готовый каталог),
# анализирует все секции и печатает отчёт «что не так и куда смотреть».
# Запускается на машине инженера: нужен только python 3.8+ (docker не нужен,
# pyyaml опционален — без него пропускается только разбор values).

import os
import re
import tarfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter

# ---СТАТУСЫ И ЦВЕТА---#

STATUS_CRIT = "CRIT"
STATUS_WARN = "WARN"
STATUS_INFO = "INFO"

STATUS_ORDER = {STATUS_CRIT: 0, STATUS_WARN: 1, STATUS_INFO: 2}

COLORS = {
    STATUS_CRIT: "\033[91m",
    STATUS_WARN: "\033[93m",
    STATUS_INFO: "\033[96m",
}


def colorize(status, text):
    if args.no_color:
        return text
    color = COLORS.get(status, "")
    end = "\033[0m" if color else ""
    return "%s%s%s" % (color, text, end)


# ---ПАТТЕРНЫ ОШИБОК В ЛОГАХ (как в analyze_logs.py)---#

LOG_ERROR_PATTERNS = [
    ("FATAL", re.compile(r"\bFATAL\b")),
    ("ERROR", re.compile(r"\bERROR\b")),
    ("OOM", re.compile(r"OOMKilled|Out of memory|oom-killer|Killed process \d+")),
    ("panic", re.compile(r"panic:")),
    ("NEW EXCEPTION", re.compile(r"NEW EXCEPTION")),
    ("MySQL gone away", re.compile(r"MySQL server has gone away")),
    ("deadlock", re.compile(r"Deadlock found", re.IGNORECASE)),
    ("Segmentation fault", re.compile(r"Segmentation fault")),
    ("exit 255", re.compile(r"exit(ed )?(with|status)? ?(code )?255\b")),
    ("connection refused", re.compile(r"Connection refused", re.IGNORECASE)),
    ("timeout", re.compile(r"\btimeout\b|\bcontext deadline exceeded\b", re.IGNORECASE)),
]

# известные run-once сервисы: для них 0/1 и успешное завершение — норма
RUN_ONCE_SERVICE_PREFIXES = ("default-file", "jitsi-custom")

# локальный загрузчик базы знаний (не импортируем common.py: он тянет pyyaml на верхнем уровне,
# а analyze_bundle должен работать вообще без зависимостей; yaml здесь — опционально)
def load_errors_kb():
    try:
        import re as re_module
        import yaml as yaml_module

        kb_path = Path(__file__).resolve().parent / "errors_kb.yaml"
        if not kb_path.exists():
            return []

        data = yaml_module.safe_load(kb_path.read_text(encoding="utf-8")) or {}
        entries = []
        for raw in (data.get("entries") or []):
            compiled_patterns = []
            for pattern in (raw.get("patterns") or []):
                try:
                    compiled_patterns.append(re_module.compile(pattern))
                except re_module.error:
                    continue
            if compiled_patterns:
                entries.append({
                    "id": raw.get("id", ""),
                    "title": raw.get("title", ""),
                    "cause": (raw.get("cause") or "").strip(),
                    "fix": (raw.get("fix") or "").strip(),
                    "severity": raw.get("severity", "warn"),
                    "doc": raw.get("doc", ""),
                    "patterns": compiled_patterns,
                })
        return entries
    except Exception:
        return []


def match_error_kb(kb_entries, line):
    for entry in kb_entries:
        for pattern in entry["patterns"]:
            if pattern.search(line):
                return entry
    return None

# форматы времени в начале строк логов (go/php)
TIMESTAMP_RES = [
    re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}):\d{2}"),
    re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})"),
    re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}):\d{2}"),
]

# ---АРГУМЕНТЫ---#

import argparse

parser = argparse.ArgumentParser(
    description="Разбор информационного бандла Compass On-premise (collect_info.py): отчёт по проблемам.",
    usage="python3 analyze_bundle.py <бандл.tar.gz или каталог> [--top N] [--no-color]",
    epilog="Примеры:\n"
           "  python3 analyze_bundle.py /tmp/compass_info_host_20260826.tar.gz\n"
           "  python3 analyze_bundle.py ./compass_info_host_20260826 --top 30\n"
           "\n"
           "Код завершения: 0 — всегда (аналитический инструмент).",
)
parser.add_argument("bundle", type=str, help="Путь к tar.gz бандла или к распакованному каталогу")
parser.add_argument("--top", required=False, default=15, type=int, help="Сколько проблем показывать в сводке")
parser.add_argument("--samples", required=False, default=3, type=int, help="Примеров строк лога на паттерн")
parser.add_argument("--timeline", required=False, default=15, type=int, help="Сколько событий показывать в таймлайне")
parser.add_argument("--no-color", required=False, action="store_true", help="Отключить цветной вывод")
args = parser.parse_args()

NO_COLOR = args.no_color

# ---НАКОПЛЕНИЕ НАХОДОК---#

# находка: (статус, раздел, заголовок, детали, источник)
FINDINGS = []

# таймлайн событий: (datetime или строка часа, описание, источник) — печатается отдельной секцией
TIMELINE = []


def add_finding(status, section, title, details="", source=""):
    FINDINGS.append({
        "status": status,
        "section": section,
        "title": title,
        "details": str(details),
        "source": source,
    })


# ---ВСКРЫТИЕ БАНДЛА---#

# распаковать архив в temp-каталог с защитой от path traversal
def extract_bundle(bundle_path):
    extract_dir = Path(tempfile.mkdtemp(prefix="compass_bundle_"))

    with tarfile.open(bundle_path, "r:gz") as tar:
        for member in tar.getmembers():
            member_name = member.name
            if member_name.startswith("/") or ".." in Path(member_name).parts:
                continue  # небезопасные пути пропускаем
            tar.extract(member, extract_dir)

    # внутри архива каталог с именем бандла
    children = list(extract_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0], extract_dir

    return extract_dir, extract_dir


# прочитать файл бандла (вернуть текст или "")
def read_text(bundle_dir, relative_path):
    path = bundle_dir / relative_path
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


# ---ХЕЛПЕРЫ ПАРСИНГА---#

# выполнить regex по всем строкам текста
def grep_lines(text, pattern):
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    return [line for line in text.splitlines() if compiled.search(line)]


# вытащить блок после "$ команда" до следующей "$ " или конца
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


# размер вида "1.5Gi"/"500Mi"/"1.2GB" в гигабайтах
def parse_size_gb(text):
    match = re.search(r"([\d.]+)\s*([GMK]i?B?)", text, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2).upper().rstrip("IB")
    multipliers = {"G": 1, "M": 1 / 1024, "K": 1 / 1024 ** 2}
    if unit not in multipliers:
        return None
    return value * multipliers[unit]


# ---ПАРСЕР: СИСТЕМА---#

def parse_system(bundle_dir):
    text = read_text(bundle_dir, "system.txt")
    if not text:
        add_finding(STATUS_WARN, "Система", "system.txt отсутствует", "бандл собран без секции системы")
        return

    # ос и uptime — в инфо
    pretty = grep_lines(text, r"^PRETTY_NAME=")
    if pretty:
        add_finding(STATUS_INFO, "Система", "ОС", pretty[0].split("=", 1)[1].strip('"'))

    # диск
    df_block = command_block(text, "df -h")
    seen_mounts = set()
    for line in df_block.splitlines():
        fields = line.split()
        if len(fields) < 6 or not re.match(r"^\d+%", fields[4]):
            continue
        used_percent = int(fields[4].rstrip("%"))
        mount = fields[-1]
        if mount in seen_mounts:
            continue
        seen_mounts.add(mount)
        if used_percent >= 90:
            add_finding(STATUS_CRIT, "Диск", "Раздел %s занят на %d%%" % (mount, used_percent),
                        "строка df: %s" % line, "system.txt")
        elif used_percent >= 80:
            add_finding(STATUS_WARN, "Диск", "Раздел %s занят на %d%%" % (mount, used_percent),
                        "строка df: %s" % line, "system.txt")

    # память
    free_block = command_block(text, "free -h")
    for line in free_block.splitlines():
        fields = line.split()
        if not fields or fields[0] != "Mem:" or len(fields) < 4:
            continue
        total_gb = parse_size_gb(fields[1])
        available_gb = parse_size_gb(fields[-1])
        if total_gb and available_gb is not None:
            available_percent = 100.0 * available_gb / total_gb
            if available_percent < 5:
                add_finding(STATUS_CRIT, "Память", "Доступно %.0f%% памяти (%.1f ГБ из %.1f ГБ)" % (
                    available_percent, available_gb, total_gb), line, "system.txt")
            elif available_percent < 10:
                add_finding(STATUS_WARN, "Память", "Доступно %.0f%% памяти (%.1f ГБ из %.1f ГБ)" % (
                    available_percent, available_gb, total_gb), line, "system.txt")
        break


# ---ПАРСЕР: DOCKER---#

def parse_docker(bundle_dir):
    text = read_text(bundle_dir, "docker.txt")
    if not text:
        add_finding(STATUS_WARN, "Docker", "docker.txt отсутствует")
        return

    # версии и количество контейнеров
    server_version = grep_lines(text, r"^\s*Server Version:")
    running = grep_lines(text, r"^\s*Running:")
    stopped = grep_lines(text, r"^\s*Stopped:")
    if server_version:
        add_finding(STATUS_INFO, "Docker", "Версия docker", server_version[0].strip(), "docker.txt")
    if running and stopped:
        add_finding(STATUS_INFO, "Docker", "Контейнеры", "running=%s, stopped=%s (из docker info)" % (
            running[0].split(":")[1].strip(), stopped[0].split(":")[1].strip()), "docker.txt")

    # ноды
    node_block = command_block(text, "docker node ls")
    for line in node_block.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] == "ID":
            continue
        # колонки: ID [«*» для текущей ноды] Hostname Status Availability ...
        if fields[1] == "*":
            hostname, node_state, availability = fields[2], fields[3], fields[4]
        else:
            hostname, node_state, availability = fields[1], fields[2], fields[3]
        if node_state.lower() != "ready":
            add_finding(STATUS_CRIT, "Ноды", "Нода %s в состоянии %s" % (hostname, node_state), line, "docker.txt")
        elif availability == "Drain":
            add_finding(STATUS_WARN, "Ноды", "Нода %s переведена в drain" % hostname, line, "docker.txt")

    # сервисы: реплики (колонки: ID NAME MODE REPLICAS IMAGE [PORTS])
    service_block = command_block(text, "docker service ls")
    broken_services = []
    for line in service_block.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] == "ID":
            continue
        name = fields[1]
        replicas = next((field for field in fields[2:5] if re.fullmatch(r"\d+/\d+", field)), "")
        if not replicas:
            continue
        try:
            running_count, desired_count = [int(part) for part in replicas.split("/")]
        except ValueError:
            continue
        if running_count < desired_count:
            if any(prefix in name for prefix in RUN_ONCE_SERVICE_PREFIXES):
                continue
            broken_services.append("%s (%d/%d)" % (name, running_count, desired_count))

    if broken_services:
        add_finding(STATUS_CRIT, "Сервисы", "Не запущено сервисов: %d" % len(broken_services),
                    ", ".join(broken_services), "docker.txt")

    # место, которое можно освободить
    df_block = command_block(text, "docker system df")
    for line in df_block.splitlines():
        match = re.search(r"\((\d+)%\)\s*$", line)
        if match and int(match.group(1)) >= 50:
            add_finding(STATUS_WARN, "Docker", "Много reclaimable-данных (docker system df)",
                        "%s — можно почистить (docker system prune)" % line.strip(), "docker.txt")

    # docker ps -a: exited/restarting контейнеры
    ps_block = command_block(text, "docker ps -a")
    exit_codes = Counter()
    for line in ps_block.splitlines():
        match = re.search(r"\b(Exited|Restarting)\s*\((\d+)\)", line)
        if match:
            exit_codes["%s(%s)" % (match.group(1), match.group(2))] += 1
    for code, count in exit_codes.most_common(5):
        if code.startswith("Restarting"):
            add_finding(STATUS_CRIT, "Сервисы", "Контейнер в состоянии Restarting ×%d" % count,
                        "коды: %s" % code, "docker.txt")
        elif code not in ("Exited(0)",):
            add_finding(STATUS_WARN, "Сервисы", "Завершённые контейнеры %s ×%d" % (code, count),
                        "", "docker.txt")


# ---ПАРСЕР: УПАВШИЕ ЗАДАЧИ---#

def parse_failed_tasks(bundle_dir):
    text = read_text(bundle_dir, "docker_failed_tasks.txt")
    if not text or "не найдено" in text:
        return

    fatal_codes = []
    other = []
    for line in text.splitlines():
        match = re.search(r"non-zero exit \((\d+)\)", line)
        if not match:
            continue
        code = int(match.group(1))
        if code in (137, 255, 139, 134):
            fatal_codes.append(line.strip())
        else:
            other.append(line.strip())

    if fatal_codes:
        add_finding(STATUS_CRIT, "Задачи", "Фатальные коды завершения задач ×%d" % len(fatal_codes),
                    "\n    ".join(fatal_codes[:5]), "docker_failed_tasks.txt")
    if other:
        add_finding(STATUS_WARN, "Задачи", "Задачи с ненулевым кодом ×%d" % len(other),
                    "\n    ".join(other[:5]), "docker_failed_tasks.txt")


# ---ПАРСЕР: УСТАНОВЩИК И КОНФИГИ---#

def parse_installer(bundle_dir):
    text = read_text(bundle_dir, "installer.txt")
    if not text:
        add_finding(STATUS_WARN, "Инсталлятор", "installer.txt отсутствует")
        return

    for line in text.splitlines():
        if line.startswith("version:"):
            add_finding(STATUS_INFO, "Инсталлятор", "Версия инсталлятора", line.split(":", 1)[1].strip(), "installer.txt")
        if line.startswith("git") or "origin/" in line or re.match(r"^\*?\s?[a-f0-9]{7} ", line):
            pass  # ветка/коммит — просто контекст, не находка
        if line.startswith("security.yaml:"):
            if "права 0o600" not in line:
                add_finding(STATUS_WARN, "Инсталлятор", "security.yaml доступен шире, чем 600",
                            line, "installer.txt")

    # values: плейсхолдеры и ключевые настройки
    values_path = bundle_dir / "config" / "values_env.redacted.yaml"
    if values_path.is_file():
        try:
            import yaml

            values = yaml.safe_load(values_path.read_text()) or {}

            host = values.get("host")
            if host in (None, "", "example.com"):
                add_finding(STATUS_CRIT, "Конфигурация",
                            "host в values не задан или это плейсхолдер (%r)" % host,
                            "наружные адреса и push-уведомления работать не будут; "
                            "проверьте src/values.*.yaml и cert/домен", "config/values_env.redacted.yaml")

            root_mount = values.get("root_mount_path")
            if root_mount:
                add_finding(STATUS_INFO, "Конфигурация", "root_mount_path", root_mount, "installer.txt")

            enabled = []
            if (values.get("projects", {}) or {}).get("outlook_add_in", {}).get("is_enabled"):
                enabled.append("outlook_add_in")
            if (values.get("siem", {}) or {}).get("enabled_driver") == "kafka":
                enabled.append("siem/kafka")
            if values.get("local_license"):
                enabled.append("local_license")
            add_finding(STATUS_INFO, "Конфигурация", "Включённые опции",
                        ", ".join(enabled) if enabled else "нет доп. опций", "config/values_env.redacted.yaml")

        except ImportError:
            add_finding(STATUS_INFO, "Конфигурация", "pyyaml не установлен",
                        "разбор values пропущен (pip3 install pyyaml — если нужно)")
    else:
        add_finding(STATUS_WARN, "Конфигурация", "values в бандле нет",
                    "collect_info не смог прочитать values на сервере — см. installer.txt")


# ---ПАРСЕР: СЕРТИФИКАТЫ---#

def parse_certs(bundle_dir):
    text = read_text(bundle_dir, "certs.txt")
    if not text:
        return

    for match in re.finditer(r"^([\w.\-]+):\s*\nnotAfter=(.+)$", text, re.MULTILINE):
        cert_name, raw_date = match.group(1), match.group(2).strip()
        try:
            expires = datetime.strptime(raw_date, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 7:
            add_finding(STATUS_CRIT, "Сертификаты", "%s истекает через %d дн." % (cert_name, days_left),
                        raw_date, "certs.txt")
        elif days_left < 30:
            add_finding(STATUS_WARN, "Сертификаты", "%s истекает через %d дн." % (cert_name, days_left),
                        raw_date, "certs.txt")


# ---ПАРСЕР: MYSQL---#

def parse_mysql(bundle_dir):
    text = read_text(bundle_dir, "mysql.txt")
    if not text:
        return

    sections = re.split(r"^== ", text, flags=re.MULTILINE)[1:]
    for section in sections:
        container_name = section.splitlines()[0].strip()
        body = section

        # ключевые базы есть только в mysql монолита — определяем по имени контейнера
        databases_block = command_block(body, "databases") if "$ " in body else ""
        if "SHOW DATABASES" in body or databases_block:
            db_lines = body.split("databases:")[1].splitlines() if "databases:" in body else []
            databases = [line.strip() for line in db_lines if line.strip()]
            if "company_mysql" not in container_name and len(databases) > 5:
                missing = [name for name in ("pivot_system", "company_system") if name not in databases]
                if missing:
                    add_finding(STATUS_WARN, "MySQL", "В %s нет баз: %s" % (container_name, ", ".join(missing)),
                                "всего баз: %d" % len(databases), "mysql.txt")

        if "креды не подобраны" in body:
            add_finding(STATUS_WARN, "MySQL", "Не удалось подключиться к %s" % container_name,
                        "креды не подобраны на момент сбора бандла", "mysql.txt")


# ---ПАРСЕР: ОТЧЁТ DIAGNOSE---#

def parse_diagnose(bundle_dir):
    text = read_text(bundle_dir, "diagnose.txt")
    if not text:
        add_finding(STATUS_INFO, "Diagnose", "diagnose.txt в бандле нет",
                    "бандл собран с --no-diagnose или diagnose упал")
        return

    for line in text.splitlines():
        match = re.match(r"^\s{2}\[\s*(FAIL|WARN)\s*\]\s*(.+?)\s*:\s*(.+)$", line)
        if not match:
            continue
        status, name = match.group(1), match.group(2)
        message = match.group(3)
        if status == "FAIL":
            add_finding(STATUS_CRIT, "Diagnose", name, message, "diagnose.txt")
        else:
            add_finding(STATUS_WARN, "Diagnose", name, message, "diagnose.txt")


# ---АНАЛИЗ ЛОГОВ---#

# убрать префикс задачи docker из строки лога
def strip_log_prefix(line):
    if " | " in line:
        return line.split(" | ", 1)[1]
    return line


# нормализовать сообщение: цифры -> N, для группировки одинаковых ошибок
def normalize_message(message):
    normalized = re.sub(r"\d+", "N", message)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized[:160]


# определить час события по метке времени в начале строки
def extract_hour(line):
    for timestamp_re in TIMESTAMP_RES:
        match = timestamp_re.match(line)
        if match:
            return match.group(1)[:13]
    return None


def analyze_logs(bundle_dir):
    logs_dir = bundle_dir / "logs"
    if not logs_dir.is_dir():
        return

    pattern_stats = defaultdict(lambda: defaultdict(int))  # сервис -> паттерн -> счёт
    samples = defaultdict(list)  # (сервис, паттерн) -> строки
    hour_stats = defaultdict(Counter)  # сервис -> час -> счёт
    repeated = defaultdict(Counter)  # сервис -> нормализованное сообщение -> счёт
    kb_hits = defaultdict(lambda: defaultdict(int))  # сервис -> kb_id -> счёт
    kb_entries = load_errors_kb()

    for log_path in sorted(logs_dir.glob("*.log")):
        service_name = log_path.stem
        try:
            lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for line in lines:
            clean_line = strip_log_prefix(line)
            matched_any = False
            for pattern_name, pattern in LOG_ERROR_PATTERNS:
                if pattern.search(clean_line):
                    pattern_stats[service_name][pattern_name] += 1
                    if len(samples[(service_name, pattern_name)]) < args.samples:
                        samples[(service_name, pattern_name)].append(clean_line.strip()[:300])
                    matched_any = True
            if not matched_any:
                continue

            # строка уже похожа на ошибку — сверяем с базой известных проблем
            if kb_entries:
                kb_entry = match_error_kb(kb_entries, clean_line)
                if kb_entry:
                    kb_hits[service_name][kb_entry["id"]] += 1

            hour = extract_hour(clean_line)
            if hour:
                hour_stats[service_name][hour] += 1
            repeated[service_name][normalize_message(clean_line)] += 1

    # часы с ошибками каждого сервиса — в общий таймлайн
    for service_name, hours in hour_stats.items():
        for hour, count in hours.items():
            TIMELINE.append((hour, "%d ошибок: %s" % (count, service_name),
                             "logs/%s.log" % service_name))

    # сводка по сервисам
    totals = []
    for service_name, per_pattern in pattern_stats.items():
        total = sum(per_pattern.values())
        totals.append((total, service_name, per_pattern))
    totals.sort(reverse=True)

    for total, service_name, per_pattern in totals[:args.top]:
        breakdown = ", ".join("%s×%d" % item for item in sorted(per_pattern.items(), key=lambda item: -item[1]))
        status = STATUS_CRIT if total >= 100 else STATUS_WARN
        add_finding(status, "Логи", "%s: %d ошибок за период" % (service_name, total),
                    breakdown, "logs/%s.log" % service_name)

        # часы-пики — когда начались проблемы
        hours = hour_stats.get(service_name)
        if hours:
            peak_hours = ", ".join("%s (%d)" % item for item in hours.most_common(3))
            add_finding(STATUS_INFO, "Логи", "  ↳ пики ошибок %s" % service_name, peak_hours, "logs/%s.log" % service_name)

        # самое частое сообщение
        top_messages = repeated.get(service_name)
        if top_messages:
            message, count = top_messages.most_common(1)[0]
            if count >= 5:
                add_finding(STATUS_INFO, "Логи", "  ↳ чаще всего (×%d): %s" % (count, message[:200]),
                            "", "logs/%s.log" % service_name)

    # известные проблемы из базы знаний — отдельным разделом с рецептами
    if not kb_hits or not kb_entries:
        return

    entries_by_id = dict((entry["id"], entry) for entry in kb_entries)
    for service_name, per_id in kb_hits.items():
        for kb_id, count in sorted(per_id.items(), key=lambda item: -item[1]):
            entry = entries_by_id.get(kb_id)
            if not entry:
                continue

            status = STATUS_CRIT if entry["severity"] == "crit" else STATUS_WARN
            details_parts = []
            if entry["cause"]:
                details_parts.append("причина:   %s" % entry["cause"])
            if entry["fix"]:
                details_parts.append("лечение:  %s" % entry["fix"])
            if entry["doc"]:
                details_parts.append("доки:     %s" % entry["doc"])

            add_finding(status, "Известные проблемы",
                        "%s: %s ×%d" % (service_name, entry["title"], count),
                        "\n".join(details_parts), "logs/%s.log" % service_name)


# отдельно: примеры строк для сводки проблем
def print_log_samples(bundle_dir):
    logs_dir = bundle_dir / "logs"
    if not logs_dir.is_dir():
        return

    print(colorize(STATUS_INFO, "── Примеры ошибок из логов " + "─" * 40))
    shown = 0
    for log_path in sorted(logs_dir.glob("*.log")):
        service_name = log_path.stem
        printed_for_service = 0
        try:
            lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for line in lines:
            clean_line = strip_log_prefix(line)
            if any(pattern.search(clean_line) for _, pattern in LOG_ERROR_PATTERNS):
                print("  %s: %s" % (service_name, clean_line.strip()[:250]))
                printed_for_service += 1
                shown += 1
                if printed_for_service >= args.samples:
                    break
        if shown >= args.samples * 5:
            break
    if shown == 0:
        print("  (совпадений с паттернами ошибок нет)")
    print("")


# ---ТАЙМЛАЙН И РЕСТАРТ-ШТОРМ---#

# возраст вида "6 days ago" / "About a minute ago" в секундах
def parse_relative_age(text):
    match = re.search(r"(\d+)\s+(second|minute|hour|day|week|month)s?\s+ago", text or "")
    if match:
        multipliers = {"second": 1, "minute": 60, "hour": 3600, "day": 86400,
                       "week": 604800, "month": 2592000}
        return int(match.group(1)) * multipliers[match.group(2)]
    if re.search(r"about an? .+ ago", text or ""):
        return 60
    return None


# дата сбора бандла из system.txt (вывод date) — привязка относительных времён
def parse_bundle_date(bundle_dir):
    text = read_text(bundle_dir, "system.txt")
    if not text:
        return None

    for line in text.splitlines():
        if re.match(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} \w+ \d{4}$", line.strip()):
            try:
                return datetime.strptime(line.strip(), "%a %b %d %H:%M:%S %Z %Y")
            except ValueError:
                break

    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", text)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M")
        except ValueError:
            pass
    return None


# события из упавших задач + рестарт-шторм из docker ps -a
def parse_timeline_and_restarts(bundle_dir):
    from datetime import timedelta

    bundle_date = parse_bundle_date(bundle_dir)

    # упавшие задачи: "Failed 6 days ago" -> примерное абсолютное время
    tasks_text = read_text(bundle_dir, "docker_failed_tasks.txt")
    if tasks_text and "не найдено" not in tasks_text and bundle_date:
        for line in tasks_text.splitlines():
            age_seconds = parse_relative_age(line)
            if age_seconds is None:
                continue

            exit_match = re.search(r"non-zero exit \((\d+)\)", line)
            name_match = re.search(r"([\w\-]+_(?:[\w\-]+))", line)
            description = "задача упала"
            if exit_match:
                description = "задача упала (exit %s)" % exit_match.group(1)
            if name_match:
                description += ": %s" % name_match.group(1).split("_")[-1]

            event_time = bundle_date - timedelta(seconds=age_seconds)
            TIMELINE.append((event_time.strftime("%Y-%m-%d %H:%M"), description, "docker_failed_tasks.txt"))

    # рестарт-шторм: контейнер живёт давно, но Up недавно — значит перезапускался
    docker_text = read_text(bundle_dir, "docker.txt")
    ps_block = command_block(docker_text, "docker ps -a") if docker_text else ""
    storm = []
    for line in ps_block.splitlines():
        up_match = re.search(r"\bUp (?:\d+ seconds?|Less than a second|\d+ minutes?|About a minute)\b", line)
        if not up_match:
            continue
        created_match = re.search(r"\b\d+ (?:hours?|days?|weeks?|months?) ago\b", line)
        if not created_match:
            continue

        fields = line.split()
        storm.append(fields[-1] if fields else line.strip()[:60])

    if len(storm) >= 3:
        add_finding(STATUS_WARN, "Рестарт-шторм",
                    "Контейнеры недавно перезапущены при давнем создании (%d)" % len(storm),
                    "\n".join("      %s" % name for name in storm[:10]) +
                    "\n      смотрите docker service ps <сервис> и логи: вероятно, падают по кругу",
                    "docker.txt")
    elif storm:
        add_finding(STATUS_INFO, "Рестарт-шторм",
                    "Недавно перезапущен 1 контейнер (%s)" % storm[0], "", "docker.txt")


# напечатать таймлайн (сортировка по времени, новые сверху)
def print_timeline():
    if not TIMELINE:
        return

    def sort_key(item):
        # форматы разные ("2026/08/26 12" из логов и "2026-08-26 14:36" из задач) —
        # приводим к одному виду, чтобы сортировка была честной
        return str(item[0]).replace("/", "-")

    print(colorize(STATUS_INFO, "── Таймлайн событий (по логам и упавшим задачам) " + "─" * 30))
    for event_time, description, source in sorted(TIMELINE, key=sort_key, reverse=True)[:max(1, args.timeline)]:
        print("  %-18s %s" % (event_time, description))
    print("")


# ---ОТЧЁТ---#

def print_report(bundle_dir):
    counts = Counter(finding["status"] for finding in FINDINGS)

    print("")
    print(colorize(STATUS_INFO, "Разбор бандла: %s" % bundle_dir.name))
    print("  Находок: критичных %s, внимания %s, справочно %s" % (
        colorize(STATUS_CRIT, str(counts.get(STATUS_CRIT, 0))),
        colorize(STATUS_WARN, str(counts.get(STATUS_WARN, 0))),
        counts.get(STATUS_INFO, 0),
    ))
    print("")

    # сводка: сначала критичные
    ordered = sorted(FINDINGS, key=lambda finding: STATUS_ORDER[finding["status"]])

    print(colorize(STATUS_INFO, "── Сводка проблем " + "─" * 44))
    for index, finding in enumerate(ordered[:args.top], start=1):
        source_suffix = " [%s]" % finding["source"] if finding["source"] else ""
        print("  %s %d. %s%s" % (
            colorize(finding["status"], "[%s]" % finding["status"]),
            index,
            finding["title"],
            source_suffix,
        ))
    print("")

    # детали по разделам
    sections = []
    for finding in ordered:
        if finding["section"] not in sections:
            sections.append(finding["section"])

    for section in sections:
        section_findings = [finding for finding in ordered if finding["section"] == section]
        print(colorize(STATUS_INFO, "── %s " % section).ljust(78, "─") if not NO_COLOR
              else ("── %s " % section).ljust(78, "─"))
        for finding in section_findings:
            source_suffix = " [%s]" % finding["source"] if finding["source"] else ""
            print("  %s %s%s" % (colorize(finding["status"], "[%s]" % finding["status"]),
                                 finding["title"], source_suffix))
            if finding["details"]:
                for detail_line in finding["details"].splitlines()[:4]:
                    print("       %s" % detail_line.strip()[:250])
        print("")


# ---ТОЧКА ВХОДА---#

def main():
    bundle_path = Path(args.bundle).expanduser().resolve()
    if not bundle_path.exists():
        print("Не найден бандл: %s" % bundle_path)
        sys.exit(1)

    temp_root = None
    if bundle_path.is_file():
        bundle_dir, temp_root = extract_bundle(bundle_path)
    else:
        bundle_dir = bundle_path

    try:
        # каждый парсер изолирован: упавший не ломает остальные
        parsers = [
            ("система", lambda: parse_system(bundle_dir)),
            ("docker", lambda: parse_docker(bundle_dir)),
            ("задачи", lambda: parse_failed_tasks(bundle_dir)),
            ("инсталлятор", lambda: parse_installer(bundle_dir)),
            ("сертификаты", lambda: parse_certs(bundle_dir)),
            ("mysql", lambda: parse_mysql(bundle_dir)),
            ("diagnose", lambda: parse_diagnose(bundle_dir)),
            ("логи", lambda: analyze_logs(bundle_dir)),
            ("таймлайн", lambda: parse_timeline_and_restarts(bundle_dir)),
        ]
        import traceback

        for parser_name, parser_func in parsers:
            try:
                parser_func()
            except Exception:
                add_finding(STATUS_WARN, "Разбор", "Секция %s упала с исключением" % parser_name,
                            traceback.format_exc(limit=3))

        print_report(bundle_dir)
        print_timeline()
        print_log_samples(bundle_dir)
    finally:
        if temp_root:
            shutil.rmtree(temp_root, ignore_errors=True)

    sys.exit(0)


if __name__ == "__main__":
    main()
