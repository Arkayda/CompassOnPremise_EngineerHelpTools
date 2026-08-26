# CompassOnPremise EngineerHelpTools

Инструменты инженера для диагностики и тестирования установленного окружения Compass On-premise.
Закрытый внутренний репозиторий — **не входит в поставку инсталлятора** и не выполняется на проде;
репозиторий (или отдельные скрипты) копируется на сервер, когда нужно проверить окружение клиента.

Скрипты самодостаточны: зависят только от `common.py` из этого же репозитория и модулей,
которые уже есть на любой развёрнутой установке.

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

Проверяет конфигурацию (сверка values ↔ swarm), инфраструктуру, все сервисы и контейнеры,
HTTP-доступность, базы данных, kafka, ошибки в логах и бэкапы. Не останавливается на
исключениях: упавшая проверка помечается FAIL, остальные выполняются.

```bash
python3 diagnose.py -e production -v compass                  # полный отчёт в консоль (цветной)
python3 diagnose.py --only services,db,logs                   # только выбранные группы
python3 diagnose.py --json > /tmp/diagnose.json               # машиночитаемый отчёт
python3 diagnose.py --since 24h --http-timeout 5              # глубже по логам, быстрее по http
```

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
exit 255, connection refused, timeout) за период по всем сервисам, показывает топ и примеры строк.

```bash
python3 analyze_logs.py --since 24h                           # сводка за сутки
python3 analyze_logs.py --since 3d --service mysql            # один сервис
python3 analyze_logs.py --pattern 'socket.*refused' --dump    # свой regex + все строки
python3 analyze_logs.py --pattern 'MY-CODE' --pattern-only    # только свой паттерн
```

## Структура

- `common.py` — общие хелперы: цвета, загрузка values, автопоиск каталога инсталлятора,
  подбор кредов mysql (env → Docker Secrets → values), docker exec
- `diagnose.py` — полная диагностика окружения
- `collect_info.py` — сбор информационного бандла для поддержки
- `analyze_logs.py` — анализ логов сервисов после инцидента

## Добавление своих проверок в diagnose.py

Каждая проверка — функция с декоратором `@check("группа", "имя")`, внутри она вызывает
`ctx.record(group, name, статус, пояснение)`. Исключения перехватываются автоматически.
Новые группы добавляются в `GROUPS` (порядок вывода) и в список в epilog.

