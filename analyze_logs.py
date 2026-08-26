#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Офлайн-анализ логов сервисов: за период собираем логи всех (или выбранных) сервисов,
# считаем совпадения по паттернам ошибок, показываем топ сервисов и примеры строк.
# Полезно после инцидента: быстро понять, кто и чем шумел.
#
# Часть набора инструментов tools/ — работает отдельно от репозитория инсталлятора.

import re
from collections import defaultdict

from common import (
    assert_root, blue, warning, error, create_parser, run_cmd,
)

assert_root()

# ---КОНСТАНТЫ---#

# паттерны ошибок по умолчанию
DEFAULT_PATTERNS = [
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

# сколько строк лога сервиса забираем за период
DEFAULT_LOG_TAIL = 5000

# ---АРГУМЕНТЫ СКРИПТА---#

parser = create_parser(
    description="Анализ логов сервисов Compass On-premise за период: счётчики ошибок по паттернам и примеры строк.",
    usage="python3 analyze_logs.py [--since PERIOD] [--stack NAME] [--service SUBSTR] [--pattern REGEX] [--top N]",
    epilog="Примеры:\n"
           "  python3 analyze_logs.py --since 24h\n"
           "  python3 analyze_logs.py --since 3d --service mysql\n"
           "  python3 analyze_logs.py --since 24h --pattern 'socket.*refused' --dump\n"
           "\n"
           "Возвращает код 0 всегда — это аналитический инструмент, а не проверка.",
)
parser.add_argument("--since", required=False, default="24h", type=str,
                    help="За какой период смотреть логи (формат docker: 1h, 24h, 7d)")
parser.add_argument("--stack", required=False, default="", type=str,
                    help="Фильтр по имени стека (подстрока, например production-compass-monolith)")
parser.add_argument("--service", required=False, default="", type=str,
                    help="Фильтр по имени сервиса (подстрока)")
parser.add_argument("--pattern", required=False, default="", type=str,
                    help="Дополнительный свой паттерн (regex, добавляется к встроенным)")
parser.add_argument("--pattern-only", required=False, action="store_true",
                    help="Искать только своим паттерном (--pattern), без встроенных")
parser.add_argument("--top", required=False, default=20, type=int,
                    help="Сколько сервисов показать в топе")
parser.add_argument("--samples", required=False, default=3, type=int,
                    help="Сколько примеров строк на паттерн")
parser.add_argument("--tail", required=False, default=DEFAULT_LOG_TAIL, type=int,
                    help="Хвост лога каждого сервиса (строк)")
parser.add_argument("--dump", required=False, action="store_true",
                    help="Вывести все совпавшие строки целиком, а не только сводку")
args = parser.parse_args()

# ---ОСНОВНОЙ ПОТОК---#

def main():
    patterns = [] if args.pattern_only else list(DEFAULT_PATTERNS)
    if args.pattern:
        try:
            patterns.append(("свой: %s" % args.pattern, re.compile(args.pattern)))
        except re.error as e:
            print(error("Некорректный regex %r: %s" % (args.pattern, e)))
            sys.exit(2)

    if not patterns:
        print(error("Не задано ни одного паттерна: укажите --pattern или уберите --pattern-only"))
        sys.exit(2)

    # список сервисов
    rc, out, err = run_cmd(["docker", "service", "ls", "--format", "{{.Name}}"], timeout=60)
    if rc != 0:
        print(error("docker service ls: %s" % (err.strip() or out.strip())))
        sys.exit(1)

    service_names = [line.strip() for line in out.splitlines() if line.strip()]
    if args.stack:
        service_names = [name for name in service_names if args.stack in name]
    if args.service:
        service_names = [name for name in service_names if args.service in name]

    if not service_names:
        print(warning("Сервисы по фильтрам не найдены"))
        sys.exit(0)

    print(blue("Анализируем %d сервисов за %s..." % (len(service_names), args.since)))

    # счётчики: {сервис: {паттерн: [count, sample_lines]}}
    stats = defaultdict(lambda: defaultdict(lambda: [0, []]))
    total_lines = 0

    for service_name in service_names:
        rc_log, out_log, _ = run_cmd(
            ["docker", "service", "logs", "--since", args.since, "--tail", str(args.tail), service_name],
            timeout=180,
        )
        if rc_log != 0:
            continue

        for line in out_log.splitlines():
            total_lines += 1
            for pattern_name, pattern in patterns:
                if pattern.search(line):
                    entry = stats[service_name][pattern_name]
                    entry[0] += 1
                    if len(entry[1]) < args.samples:
                        entry[1].append(line.strip()[:400])

    # сводка
    print("")
    print(blue("── Топ сервисов по числу совпадений ──"))
    service_totals = []
    for service_name, per_pattern in stats.items():
        total = sum(entry[0] for entry in per_pattern.values())
        service_totals.append((total, service_name, per_pattern))

    service_totals.sort(reverse=True)
    service_totals = service_totals[:args.top]

    if not service_totals:
        print("  Просмотрено %d строк логов — совпадений нет." % total_lines)
        return

    for total, service_name, per_pattern in service_totals:
        print("  %s: %s" % (service_name, warning("%d" % total)))
        for pattern_name, (count, samples) in sorted(per_pattern.items(), key=lambda item: -item[1][0]):
            print("      %-24s ×%d" % (pattern_name, count))

    # примеры строк
    print("")
    print(blue("── Примеры строк (до %d на паттерн) ──" % args.samples))
    for total, service_name, per_pattern in service_totals:
        for pattern_name, (count, samples) in sorted(per_pattern.items(), key=lambda item: -item[1][0]):
            print("")
            print("  %s [%s]:" % (service_name, pattern_name))
            for sample in samples:
                print("    %s" % sample)

    if args.dump:
        print("")
        print(blue("── Все совпавшие строки ──"))
        for service_name in service_names:
            rc_log, out_log, _ = run_cmd(
                ["docker", "service", "logs", "--since", args.since, "--tail", str(args.tail), service_name],
                timeout=180,
            )
            if rc_log != 0:
                continue
            for line in out_log.splitlines():
                if any(pattern.search(line) for _, pattern in patterns):
                    print("%s: %s" % (service_name, line.strip()[:600]))

    print("")
    print("Просмотрено строк: %d, сервисов с совпадениями: %d" % (total_lines, len(stats)))


if __name__ == "__main__":
    main()
