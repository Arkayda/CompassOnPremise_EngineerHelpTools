# CompassOnPremise EngineerHelpTools

Инструменты для проверки установленного окружения Compass On-premise на сервере.

## Требования

- root, доступ к docker socket
- python 3.8+, модули `docker`, `pyyaml`, `requests`
- каталог инсталлятора: текущая директория и выше, затем `/opt/onpremise-installer`; иначе `--installer-dir /путь`

## diagnose.py — диагностика окружения

```bash
sudo python3 diagnose.py -e production -v compass              # полный отчёт
sudo python3 diagnose.py --only services,db,logs               # выбранные группы
sudo python3 diagnose.py --since 72h --log-tail 5000           # глубже по логам
sudo python3 diagnose.py --http-timeout 5                      # быстрее по http
sudo python3 diagnose.py --json > /tmp/diagnose.json           # машиночитаемый отчёт
```

Код завершения: `0` — FAIL нет, `1` — есть.

Группы проверок:

| Группа | Что проверяет |
|---|---|
| `config` | values, security.yaml, .version (+ git-ветка инсталлятора), каталог данных, стеки swarm vs values |
| `infra` | docker daemon, swarm, ноды, диск, память, load, место образов/томов |
| `requirements` | CPU/RAM/диск/порты против минимумов из документации |
| `services` | реплики, health и рестарты контейнеров, упавшие задачи, условные сервисы |
| `http` | главная страница, пути проектов, api_gateway /health, сроки сертификатов |
| `security` | пароли по умолчанию в values, плейсхолдеры, опубликованные порты (mysql/rabbit наружу = FAIL), SSL-цепочка, маунты docker.sock |
| `external` | license/push/registry/billing/SMTP, DNS с хоста и из контейнера |
| `functional` | очередь автоудаления файлов, крон file-node, manticore |
| `db` | mysql монолита и компаний (подключение, базы, версия, аптайм, потоки), репликация, manticore |
| `kafka` | топики kafka (SIEM) |
| `logs` | ошибки в логах по паттернам (FATAL, ERROR, OOM, panic, дедлоки, gone away, exit 255, refused, timeout), топ сервисов, самое частое сообщение, часы-пиков, примеры строк |
| `backups` | свежесть и размер бэкапов |

К строкам логов и к проблемам из сводки применяется база известных проблем `errors_kb.yaml`: для совпадений выводятся причина, лечение и ссылка на документацию. В сводке проблемы идут сначала FAIL, затем WARN.

Пароли mysql подбираются автоматически: env контейнера → Docker Secrets → values.

## update_dry_run.py — аудит перед обновлением

```bash
sudo python3 update_dry_run.py -e production -v compass
sudo python3 update_dry_run.py --backup-max-age-hours 168     # допустить недельный бэкап
```

Показывает: какие миграции из `updates/` накатятся и что в них, git-состояние инсталлятора, какие сервисы сменят образ, предусловия (бэкапы, место, здоровье сервисов, доступность registry), план обновления из трёх команд. Ничего не выполняет.

Код завершения: `1` при блокирующих проблемах (место, registry).

## Структура

- `common.py` — общие хелперы: цвета, загрузка values, автопоиск инсталлятора, подбор кредов mysql, docker exec, загрузка errors_kb
- `errors_kb.yaml` — база известных проблем: regex-паттерн → причина, лечение, ссылка на doc-onpremise.getcompass.ru
- `diagnose.py` — диагностика окружения
- `update_dry_run.py` — аудит перед обновлением

## Добавление проверки в diagnose.py

Проверка — функция с декоратором `@check("группа", "имя")`, внутри вызывается `ctx.record(group, name, статус, пояснение)`. Исключения перехватываются автоматически. Новую группу добавить в `GROUPS` (порядок вывода) и в description.
