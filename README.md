# CompassOnPremise EngineerHelpTools

Инструменты для диагностики и тестирования установленного окружения Compass On-premise. Репозиторий копируется на сервер, когда нужно проверить окружение клиента.

Скрипты зависят только от common.py из этого же репозитория и модулей, которые уже есть на любой развёрнутой установке.

## Запуск

Скрипты запускаются от root тем же python, которым работает инсталлятор:

```bash
sudo python3 diagnose.py -e production -v compass        # из корня репозитория
sudo python3 collect_info.py -e production -v compass
sudo python3 analyze_logs.py --since 24h
```

Каталог инсталлятора ищется автоматически: текущая директория и выше → `/opt/onpremise-installer`.
Если он в другом месте — укажите `--installer-dir /путь`.

Требования: python 3.8+, модули `docker`, `pyyaml` (и `requests` для diagnose) — на любом
развернутом окружении уже есть. Доступ к docker socket — от root.

## diagnose.py — полная диагностика окружения

Проверяет конфигурацию (сверка values ↔ swarm), инфраструктуру, требования к серверу,
все сервисы и контейнеры, HTTP-доступность, внешние зависимости, базы данных, kafka,
ошибки в логах и бэкапы. Не останавливается на исключениях: упавшая проверка помечается
FAIL, остальные выполняются.

```bash
python3 diagnose.py -e production -v compass                  # полный отчёт в консоль (цветной)
python3 diagnose.py --only services,db,logs                   # только выбранные группы
python3 diagnose.py --json > /tmp/diagnose.json               # машиночитаемый отчёт
python3 diagnose.py --since 24h --http-timeout 5              # глубже по логам, быстрее по http
```

Группы проверок (запускаются все сразу, `--only` сужает список): `config`, `infra`,
`requirements` (CPU/RAM/диск/порты против минимумов из документации), `services`, `http`,
`external` (license/push/registry/billing/SMTP, DNS с хоста и из контейнера), `functional` (смоук-тесты: очередь
автоудаления файлов, крон, manticore), `db`, `kafka`, `logs` (включая сверку с базой
известных проблем `errors_kb.yaml` — с рецептом лечения в отчёте), `backups`.

Код завершения: `0` — критических проблем нет, `1` — есть FAIL (удобно для cron/алертов).
Пароли mysql подбираются автоматически: env контейнера → Docker Secrets → values
(работает и на классической схеме, и на ветке с секретами).

## collect_info.py — информационный бандл для поддержки

Собирает в один tar.gz всё, что нужно для разбора проблемы удалённо: состояние системы,
docker (сервисы, ноды, упавшие задачи), конфиги, сертификаты, состояние mysql, логи
сервисов за период и полный отчёт `diagnose.py`.

```bash
python3 collect_info.py -e production -v compass              # → /tmp/compass_info_<хост>_<дата>.tar.gz
python3 collect_info.py --since 72h --log-tail 2000           # глубже по логам
python3 collect_info.py --no-diagnose                         # без запуска диагностики
```

Безопасность бандла:
- значения ключей с `password/passwd/secret/token/api_key/private` в конфигах **заменяются на `***`**;
- `security.yaml` не собирается (только факт наличия и права);
- в логах сервисов секреты не редактируются — предупреждение печатается в конце, при
  критичности проверьте бандл перед пересылкой.

## analyze_logs.py — разбор логов после инцидента

Считает ошибки по встроенным паттернам (FATAL, ERROR, OOM, panic, дедлоки, gone away,
exit 255, connection refused, timeout) за период по всем сервисам, показывает топ и примеры
строк. Совпавшие строки дополнительно сверяются с базой известных проблем `errors_kb.yaml`:
для известных — причина, лечение и ссылка на документацию.

```bash
python3 analyze_logs.py --since 24h                           # сводка за сутки
python3 analyze_logs.py --since 3d --service mysql            # один сервис
python3 analyze_logs.py --pattern 'socket.*refused' --dump    # свой regex + все строки
python3 analyze_logs.py --pattern 'MY-CODE' --pattern-only    # только свой паттерн
```

## errors_kb.yaml — база известных проблем

Каталог из ~20 известных проблем Compass On-premise с regex-паттернами, причиной, лечением
и ссылкой на doc-onpremise.getcompass.ru: активация сервера, SMTP, неполная SSL-цепочка,
звонки (ICE/UDP), LDAP/OIDC, OOM автоудаления файлов (exit 255), push-401, пустой host,
mysql gone away и другие. Используется `analyze_logs.py` и `analyze_bundle.py`;
расширяется простым добавлением записей в yaml.

## analyze_bundle.py — разбор бандла на машине инженера

Вскрывает tar.gz от `collect_info.py` (или готовый каталог) и печатает готовый разбор:
сводка проблем по убыванию важности, детали по разделам (диск, память, ноды, сервисы,
упавшие задачи, конфигурация, сертификаты, mysql, находки diagnose), анализ логов
(топ сервисов по ошибкам, часы-пики, самое частое сообщение), известные проблемы из
базы знаний, таймлайн событий (часы ошибок + упавшие задачи в абсолютном времени),
детекция рестарт-шторма и примеры строк.
Требует только python 3.8+ (docker не нужен, pyyaml опционален).

```bash
python3 analyze_bundle.py /tmp/compass_info_<хост>_<дата>.tar.gz   # разбор архива
python3 analyze_bundle.py ./compass_info_<хост>_<дата> --top 30    # распакованный каталог
python3 analyze_bundle.py bundle.tar.gz --timeline 40              # глубже таймлайн
```

## bundle_diff.py — сравнение двух бандлов

Что изменилось между двумя сборками «до»/«после» (обновление, инцидент, настройка):
версия инсталлятора, состав сервисов и реплики (↑/↓), образы, упавшие задачи,
счётчики кодов завершения, динамика ошибок в логах по сервисам, diff редактированных
values, сроки сертификатов, итоги diagnose. Standalone: python 3.8+, без зависимостей.

```bash
python3 bundle_diff.py /tmp/бандл_до.tar.gz /tmp/бандл_после.tar.gz
python3 bundle_diff.py ./bundle_old ./bundle_new --no-color
```

## update_dry_run.py — аудит перед обновлением

Read-only прогон без выполнения обновления: какие миграции из `updates/` накатятся
и что в них, git-состояние инсталлятора (локальные правки = риск конфликта), какие
сервисы сменят образ, предусловия (свежесть бэкапов, место на диске, здоровье сервисов,
доступность registry) и готовый план обновления из трёх команд.

```bash
python3 update_dry_run.py -e production -v compass
python3 update_dry_run.py --backup-max-age-hours 168     # допустить недельный бэкап
```

Код завершения: `1` при блокирующих проблемах (место, registry).

## security_scan.py — аудит безопасности

Пароли-плейсхолдеры из шаблонов values (4321/root2/1234/…), плейсхолдеры конфигурации
(example.com, пустые секреты), опубликованные наружу порты vs ожидаемые из values
(mysql/rabbit/redis наружу = FAIL), полнота SSL-цепочки главного домена, права
security.yaml, маунты docker.sock.

```bash
python3 security_scan.py -e production -v compass
```

Код завершения: `1` если есть FAIL.

## fleet_status.py — статус всех стендов

Сводная таблица по всем стендам из `stands.yaml`: по SSH запускает `diagnose.py --json`
на каждом и показывает OK/WARN/FAIL/SKIP, топ проблем и время прогона. Перед первым
запуском разложите инструменты на стенды (`scp diagnose.py common.py errors_kb.yaml
user@host:/tmp/tools/`), впишите стенды в `stands.yaml` (скопировав `stands.example.yaml`;
файл в .gitignore — ключи и хосты не утекут в git).

```bash
cp stands.example.yaml stands.yaml    # впишите свои стенды
python3 fleet_status.py               # все стенды
python3 fleet_status.py --stand onpremise-test
```

Код завершения: `1` если на каком-то стенде есть FAIL или он недоступен.
Требует локально pyyaml и ssh-ключи с доступом к стендам.

## Структура

- `common.py` — общие хелперы: цвета, загрузка values, автопоиск каталога инсталлятора,
  подбор кредов mysql (env → Docker Secrets → values), docker exec, загрузка базы знаний
- `errors_kb.yaml` — база известных проблем (паттерн → причина/лечение/дока)
- `diagnose.py` — полная диагностика окружения
- `collect_info.py` — сбор информационного бандла для поддержки
- `analyze_logs.py` — анализ логов сервисов после инцидента
- `analyze_bundle.py` — офлайн-разбор бандла collect_info на машине инженера
- `bundle_diff.py` — сравнение двух бандлов «до»/«после»
- `update_dry_run.py` — аудит перед обновлением инсталлятора
- `security_scan.py` — аудит безопасности окружения
- `fleet_status.py` + `stands.example.yaml` — сводный статус стендов по SSH

## Добавление своих проверок в diagnose.py

Каждая проверка — функция с декоратором `@check("группа", "имя")`, внутри она вызывает
`ctx.record(group, name, статус, пояснение)`. Исключения перехватываются автоматически.
Новые группы добавляются в `GROUPS` (порядок вывода) и в список в epilog.

