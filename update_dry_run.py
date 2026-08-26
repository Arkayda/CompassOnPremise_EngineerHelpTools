#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Предобновленческий аудит: показывает, что произойдёт при обновлении инсталлятора,
# БЕЗ выполнения обновления. Всё выполняемое здесь — read-only.
#
# Разделы отчёта:
#   Версии      — установленная версия (.version) vs доступные миграции (updates/)
#   Миграции    — какие каталоги updates/ накатятся, что в них (скрипты/команды)
#   Git         — чистота рабочего каталога инсталлятора (обновляться лучше без локальных правок)
#   Образы      — какие сервисы сменят образ (текущий тег отсутствует в values)
#   Предусловия — бэкап, диск, состояние сервисов, доступность registry
#
# Часть набора инструментов tools/ — работает отдельно от репозитория инсталлятора.

import re
from datetime import datetime
from pathlib import Path

from common import (
    assert_root, blue, warning, error, success, create_parser, run_cmd,
    find_installer_dir, load_values,
)

assert_root()

# ---КОНСТАНТЫ---#

DISK_FREE_WARN_PERCENT = 20
DISK_FREE_FAIL_PERCENT = 10

# ---АРГУМЕНТЫ СКРИПТА---#

parser = create_parser(
    description="Аудит перед обновлением Compass On-premise: миграции, образы, предусловия (без выполнения обновления).",
    usage="python3 update_dry_run.py [-e ENVIRONMENT] [-v VALUES] [--installer-dir PATH] [--backup-max-age-hours N]",
    epilog="Примеры:\n"
           "  python3 update_dry_run.py -e production -v compass\n"
           "  python3 update_dry_run.py --backup-max-age-hours 168\n"
           "\n"
           "Код завершения: 0 — обновляться можно, 1 — есть блокирующие проблемы.",
)
parser.add_argument('-e', '--environment', required=False, default="production", type=str,
                    help="Окружение (для поиска values-файла)")
parser.add_argument('-v', '--values', required=False, default="compass", type=str,
                    help="Имя values-файла окружения")
parser.add_argument("--installer-dir", required=False, default=None, type=str,
                    help="Каталог установленного инсталлятора (по умолчанию ищется автоматически)")
parser.add_argument("--backup-max-age-hours", required=False, default=48, type=int,
                    help="Допустимый возраст последнего бэкапа в часах (по умолчанию 48)")
args = parser.parse_args()

# ---ХЕЛПЕРЫ---#

# версия вида "6.7.8" в кортеж чисел для сравнения
def version_key(text):
    parts = []
    for part in re.split(r"[.\-+]", str(text or "")):
        parts.append(int(part) if part.isdigit() else 0)
    return tuple(parts)


# собрать все значения ключей "tag" из values (рекурсивно) — это теги образов в конфиге
def collect_values_tags(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "tag" and isinstance(value, str) and value:
                found.add(value)
            else:
                collect_values_tags(value, found)
    elif isinstance(node, list):
        for item in node:
            collect_values_tags(item, found)
    return found


def print_line(text):
    print(text)


# ---ОТЧЁТЫ---#

# раздел «Версии»: установленная версия и список ожидающих миграций
def report_versions(ctx, out):
    installed = ctx["version"]
    print_line(blue(("── Версии ").ljust(78, "─")))

    if installed is None:
        print_line("  %s файл .version не найден — считается, что миграций ещё не было" % warning("[WARN]"))
        installed = "0"

    pending = [v for v in ctx["update_versions"] if version_key(v) > version_key(installed)]

    print_line("  Установлено: %s" % installed)
    print_line("  Миграций в updates/: %d, из них накатится: %s" % (
        len(ctx["update_versions"]), success(str(len(pending))) if pending else "0"))

    if not pending:
        print_line("  Обновлений не ожидается — installer_migrations_up.py ничего не применит")
        out["pending"] = []
        return

    print_line("")
    print_line(blue(("── Миграции, которые применятся ").ljust(78, "─")))
    for version in pending:
        migration_dir = ctx["updates_dir"] / version
        scripts, commands = [], 0
        migration_yaml_path = migration_dir / "migration.yaml"
        if migration_yaml_path.exists():
            try:
                import yaml

                migration_config = yaml.safe_load(migration_yaml_path.read_text()) or {}
                scripts = migration_config.get("migration_scripts") or []
                commands_list = migration_config.get("migration_commands") or []
                commands = len([c for c in commands_list if str(c).strip()])
            except Exception as e:
                print_line("  %s %s: migration.yaml не прочитался: %s" % (warning("[WARN]"), version, e))
                continue

        py_files = [p.name for p in sorted(migration_dir.glob("migration_up_*.py"))]
        print_line("  %s:" % version)
        print_line("    скриптов: %d (%s), shell-команд: %d" % (
            len(scripts) or len(py_files),
            ", ".join(scripts or py_files) or "-",
            commands,
        ))
    out["pending"] = pending


# раздел «Git»: состояние рабочего каталога инсталлятора
def report_git(ctx, out):
    print_line("")
    print_line(blue(("── Git-состояние инсталлятора ").ljust(78, "─")))

    if not (ctx["installer_dir"] / ".git").exists():
        print_line("  не git-репозиторий — пропускаем")
        return

    rc, branch, _ = run_cmd(["git", "-C", ctx["installer_dir"], "branch", "--show-current"], timeout=30)
    rc_log, last_commit, _ = run_cmd(["git", "-C", ctx["installer_dir"], "log", "-1", "--oneline"], timeout=30)
    rc_status, status, _ = run_cmd(["git", "-C", ctx["installer_dir"], "status", "--porcelain"], timeout=30)

    branch_name = branch.strip() or "(detached)"
    print_line("  Ветка: %s, HEAD: %s" % (branch_name, last_commit.strip() or "?"))

    dirty = [line for line in status.splitlines() if line.strip()]
    if dirty:
        print_line("  %s локальные правки (%d файлов) — при обновлении возможен конфликт" % (
            warning("[WARN]"), len(dirty)))
        for line in dirty[:5]:
            print_line("      %s" % line.strip())
        out["git_dirty"] = True


# раздел «Образы»: какие сервисы сменят образ при следующем деплое
def report_images(ctx, out):
    print_line("")
    print_line(blue(("── Образы сервисов ").ljust(78, "─")))

    rc, out_text, err = run_cmd(["docker", "service", "ls", "--format", "{{.Name}}|{{.Image}}"], timeout=60)
    if rc != 0:
        print_line("  %s docker service ls не выполнился: %s" % (warning("[WARN]"), err.strip()))
        return

    values_tags = collect_values_tags(ctx["values"], set())
    will_change, unchanged = [], 0

    for line in out_text.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        name, image = line.split("|", 1)
        current_tag = image.rsplit(":", 1)[-1]
        if current_tag in values_tags:
            unchanged += 1
        else:
            will_change.append((name, image))

    if will_change:
        print_line("  Сменят образ (%d) — текущий тег отсутствует в values:" % len(will_change))
        for name, image in will_change:
            print_line("      %-55s %s" % (name, image.rsplit(":", 1)[-1]))
        print_line("  (%s: эвристика «тег не найден в values» — сверяйте глазами список выше)" % "справка")
    print_line("  Без изменений (тег присутствует в values): %d сервисов" % unchanged)


# раздел «Предусловия»: бэкап, диск, сервисы, registry
def report_preconditions(ctx, out):
    print_line("")
    print_line(blue(("── Предусловия обновления ").ljust(78, "─")))

    # бэкап
    backups_dir = Path(str(ctx["values"].get("root_mount_path") or "")) / "backups"
    newest_age_hours = None
    if backups_dir.is_dir():
        newest_mtime = max(
            [path.stat().st_mtime for path in backups_dir.iterdir()] or [0]
        )
        if newest_mtime:
            newest_age_hours = (datetime.now().timestamp() - newest_mtime) / 3600

    if newest_age_hours is None:
        print_line("  %s бэкапов не найдено (%s) — перед обновлением сделайте: "
                   "python3 script/backup_db.py -e %s -v %s" % (
                       warning("[WARN]"), backups_dir, args.environment, args.values))
        out["backup_warn"] = True
    elif newest_age_hours > args.backup_max_age_hours:
        print_line("  %s последний бэкап старше %d ч (%.0f ч назад)" % (
            warning("[WARN]"), args.backup_max_age_hours, newest_age_hours))
        out["backup_warn"] = True
    else:
        print_line("  %s последний бэкап: %.0f ч назад" % (success("[ OK ]"), newest_age_hours))

    # диск
    for check_path, label in ((ctx["values"].get("root_mount_path"), "данные"), ("/var/lib/docker", "docker")):
        if not check_path:
            continue
        rc, df_out, _ = run_cmd(["df", "-P", str(check_path)], timeout=30)
        if rc != 0:
            continue
        fields = df_out.splitlines()[-1].split()
        try:
            free_percent = 100 - int(fields[4].rstrip("%"))
        except (IndexError, ValueError):
            continue
        if free_percent <= DISK_FREE_FAIL_PERCENT:
            print_line("  %s свободно %d%% на %s (%s) — мало места для обновления" % (
                error("[FAIL]"), free_percent, check_path, label))
            out["disk_fail"] = True
        elif free_percent <= DISK_FREE_WARN_PERCENT:
            print_line("  %s свободно %d%% на %s (%s) — почистите docker system prune" % (
                warning("[WARN]"), free_percent, check_path, label))
        else:
            print_line("  %s свободно %d%% на %s (%s)" % (success("[ OK ]"), free_percent, check_path, label))

    # сервисы
    rc, services_out, _ = run_cmd(["docker", "service", "ls", "--format", "{{.Replicas}}"], timeout=60)
    if rc == 0:
        broken = 0
        total = 0
        for line in services_out.splitlines():
            line = line.strip()
            if not line or "/" not in line:
                continue
            total += 1
            running, desired = line.split("/")[0], line.split("/")[1]
            try:
                if int(running) < int(desired):
                    broken += 1
            except ValueError:
                continue
        if broken:
            print_line("  %s не запущено сервисов: %d из %d — обновлять лучше на здоровом кластере "
                       "(см. diagnose.py)" % (warning("[WARN]"), broken, total))
            out["services_warn"] = True
        else:
            print_line("  %s все сервисы запущены (%d)" % (success("[ OK ]"), total))

    # registry
    try:
        import urllib.request
        import urllib.error

        urllib.request.urlopen("https://docker.getcompass.ru/v2/", timeout=10)
        reachable = True
    except urllib.error.HTTPError:
        reachable = True  # 401/403 — registry жив, просто требует авторизацию
    except Exception as e:
        reachable = False
        print_line("  %s registry docker.getcompass.ru недоступен: %s — образы не скачаются" % (
            error("[FAIL]"), e))
        out["registry_fail"] = True
    if reachable:
        print_line("  %s registry docker.getcompass.ru доступен" % success("[ OK ]"))


# ---ТОЧКА ВХОДА---#

def main():
    installer_dir = find_installer_dir(args.installer_dir)
    if not installer_dir:
        print(error("Каталог инсталлятора не найден (укажите --installer-dir)"))
        sys.exit(2)

    values, _, values_error = load_values(installer_dir, args.environment, args.values)
    if values_error:
        print(error("values не загружены: %s" % values_error))
        sys.exit(2)

    updates_dir = Path(installer_dir) / "updates"
    version_path = Path(installer_dir) / ".version"

    ctx = {
        "installer_dir": Path(installer_dir),
        "values": values,
        "updates_dir": updates_dir,
        "version": version_path.read_text().strip() if version_path.exists() else None,
        "update_versions": sorted(
            [p.name for p in updates_dir.iterdir() if p.is_dir() and version_key(p.name) > (0,)],
            key=version_key,
        ) if updates_dir.is_dir() else [],
    }

    out = {}

    print_line("")
    print_line(blue("Аудит перед обновлением Compass On-premise"))
    print_line("  Каталог:    %s" % installer_dir)
    print_line("  Окружение:  %s (values: %s)" % (args.environment, args.values))
    print_line("")

    report_versions(ctx, out)
    report_git(ctx, out)
    report_images(ctx, out)
    report_preconditions(ctx, out)

    # итог
    print_line("")
    print_line(blue(("── Итог ").ljust(78, "─")))
    blocking = [key for key in out if key.endswith("_fail")]
    if blocking:
        print_line("  %s есть блокирующие проблемы — обновляться нельзя" % error("[FAIL]"))
        sys.exit(1)

    notes = [key for key in out if key.endswith("_warn")]
    if notes:
        print_line("  %s обновляться можно, но сначала закройте предупреждения выше" % warning("[WARN]"))
    else:
        print_line("  %s обновляться можно" % success("[ OK ]"))

    print_line("")
    print_line("  План обновления:")
    print_line("    1. python3 script/backup_db.py -e %s -v %s" % (args.environment, args.values))
    print_line("    2. обновите каталог инсталлятора (git pull / новый релиз)")
    print_line("    3. python3 script/update.py -e %s" % args.environment)
    sys.exit(0)


if __name__ == "__main__":
    main()
