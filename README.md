# CompassOnPremise EngineerHelpTools

Инструменты для диагностики и тестирования установленного окружения Compass On-premise. Репозиторий копируется на сервер, когда нужно проверить окружение клиента.

Скрипты зависят только от common.py из этого же репозитория и модулей, которые уже есть на любой развёрнутой установке.

## Инструменты

Запуск от root тем же python, которым работает инсталлятор. Каталог инсталлятора ищется автоматически; если он в другом месте — `--installer-dir /путь`.

- **diagnose.py** — полная диагностика окружения: конфиги vs swarm, сервисы, HTTP, внешние зависимости, БД, логи, бэкапы.
  `python3 diagnose.py -e production -v compass` (группы: `--only services,db`; смоук-тесты: `--functional`; json: `--json`)
- **collect_info.py** — бандл для поддержки (tar.gz: система, docker, конфиги с паролями `***`, серты, mysql, логи, отчёт diagnose).
  `python3 collect_info.py -e production -v compass`
- **analyze_logs.py** — ошибки в логах сервисов за период + известные проблемы из базы знаний.
  `python3 analyze_logs.py --since 24h`
- **analyze_bundle.py** — разбор бандла collect_info на машине инженера (docker не нужен).
  `python3 analyze_bundle.py бандл.tar.gz`
- **bundle_diff.py** — сравнение двух бандлов «до/после».
  `python3 bundle_diff.py до.tar.gz после.tar.gz`
- **update_dry_run.py** — аудит перед обновлением: миграции, образы, бэкап/диск/registry.
  `python3 update_dry_run.py -e production -v compass`
- **security_scan.py** — аудит безопасности: пароли по умолчанию, опубликованные порты, SSL-цепочка, права.
  `python3 security_scan.py -e production -v compass`
- **fleet_status.py** — сводный статус всех стендов по SSH (список в stands.yaml).
  `python3 fleet_status.py`
- **errors_kb.yaml** — база известных проблем (71 запись, включая 52 ошибки из каталога инсталлятора); используется analyze_logs и analyze_bundle.
- **common.py** — общие хелперы: values, подбор кредов mysql (env → Docker Secrets → values), docker exec.
- **wiki_fetch.py / wiki_search.py** — локальная копия базы знаний Compass (вне репозитория, `~/compass-wiki`) и поиск по ней.
  `python3 wiki_fetch.py` — обновить дамп; `python3 wiki_search.py <слова>` — поиск.

## stands.yaml

Список стендов для fleet_status.py: `cp stands.example.yaml stands.yaml`, впишите свои (файл в .gitignore).

## Добавление проверок в diagnose.py

Проверка — функция с декоратором `@check("группа", "имя")`, внутри `ctx.record(group, name, статус, пояснение)`. Исключения перехватываются автоматически.
