#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Поиск по локальному дампу базы знаний Compass (~/compass-wiki, обновляется wiki_fetch.py).
# Ищет слова/фразы/regex по всем страницам, показывает совпадения со сниппетами,
# заголовком и исходным url страницы. Без зависимостей.

import re
import json
import argparse
from pathlib import Path

DEFAULT_DUMP = str(Path.home() / "compass-wiki")

parser = argparse.ArgumentParser(
    description="Поиск по локальному дампу базы знаний Compass (wiki_fetch.py).",
    usage="python3 wiki_search.py ЗАПРОС [--dump DIR] [--regex] [--top N] [--context N]",
    epilog="Примеры:\n"
           "  python3 wiki_search.py replication manticore          # все слова в одной странице\n"
           "  python3 wiki_search.py 'push 401'                     # фраза\n"
           "  python3 wiki_search.py 'push.*401' --regex            # regex\n"
           "  python3 wiki_search.py mysql --top 20 --context 2\n"
           "\n"
           "Код завершения: 0 всегда.",
)
parser.add_argument("query", nargs="+", type=str, help="Слова запроса (все должны встретиться на странице) или фраза/regex")
parser.add_argument("--dump", required=False, default=DEFAULT_DUMP, type=str,
                    help="Каталог дампа (по умолчанию ~/compass-wiki)")
parser.add_argument("--regex", required=False, action="store_true",
                    help="Интерпретировать запрос как regex (регистр не важен)")
parser.add_argument("--top", required=False, default=10, type=int,
                    help="Сколько страниц показывать")
parser.add_argument("--context", required=False, default=1, type=int,
                    help="Строк контекста вокруг совпадения")
args = parser.parse_args()

COLOR_MATCH = "\033[91m"
COLOR_TITLE = "\033[96m"
COLOR_DIM = "\033[90m"
COLOR_END = "\033[0m"

USE_COLOR = sys.stdout.isatty()


def paint(color, text):
    return "%s%s%s" % (color, text, COLOR_END) if USE_COLOR else text


# ---ЗАГРУЗКА ИНДЕКСА---#

dump_dir = Path(args.dump).expanduser()
index_path = dump_dir / "index.json"

index = {}
if index_path.exists():
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        index = {}

if not dump_dir.is_dir():
    print("Дамп не найден: %s — сначала запустите wiki_fetch.py" % dump_dir)
    sys.exit(1)


# ---ПОИСК---#

# запрос: либо regex целиком, либо набор слов (каждое должно быть на странице)
if args.regex:
    try:
        query_re = re.compile(" ".join(args.query), re.IGNORECASE)
    except re.error as e:
        print("Некорректный regex: %s" % e)
        sys.exit(1)
    word_res = None
else:
    words = [word.strip().lower() for word in " ".join(args.query).split() if word.strip()]
    if len(words) == 1:
        # одно слово — тоже подсветим совпадения
        query_re = re.compile(re.escape(words[0]), re.IGNORECASE)
    else:
        query_re = re.compile("|".join(re.escape(word) for word in words), re.IGNORECASE)
    word_res = [re.compile(re.escape(word), re.IGNORECASE) for word in words]

results = []

for md_path in sorted(dump_dir.rglob("*.md")):
    rel_path = str(md_path.relative_to(dump_dir))
    try:
        content = md_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        continue

    lines = content.splitlines()

    # источник из шапки файла
    source_url = ""
    for line in lines[:3]:
        if line.startswith("<!-- source:"):
            source_url = line.split(":", 2)[2].strip().rstrip("-->").strip()
            break

    if word_res:
        joined = content.lower()
        if not all(word_re.search(joined) for word_re in word_res):
            continue

    # строки с совпадениями + сниппеты
    matches = []
    for line_number, line in enumerate(lines, start=1):
        if query_re and query_re.search(line):
            start = max(0, line_number - 1 - args.context)
            snippet_lines = lines[start:line_number + args.context]
            matches.append((line_number, "\n".join(snippet_lines).strip()))
        if len(matches) >= 3:
            break

    if not matches:
        continue

    meta = index.get(rel_path) or {}
    results.append({
        "file": rel_path,
        "title": meta.get("title") or md_path.stem,
        "url": meta.get("url") or source_url,
        "matches": matches,
    })


# ---ВЫВОД---#

def highlight(text):
    if not query_re:
        return text
    return query_re.sub(lambda match: paint(COLOR_MATCH, match.group(0)), text)


print("")
print(paint(COLOR_TITLE, "Поиск по базе знаний Compass: %s" % " ".join(args.query)))
print(paint(COLOR_DIM, "Дамп: %s, страниц с совпадениями: %d" % (dump_dir, len(results))))
print("")

for result in results[:args.top]:
    title_line = "  %s" % paint(COLOR_TITLE, result["title"])
    if result["url"]:
        title_line += paint(COLOR_DIM, "  (%s)" % result["url"])
    print(title_line)
    print(paint(COLOR_DIM, "  файл: %s" % result["file"]))
    for line_number, snippet in result["matches"]:
        print("    %s" % paint(COLOR_DIM, ":%d" % line_number))
        for snippet_line in snippet.splitlines():
            print("      %s" % highlight(snippet_line)[:220])
    print("")

if len(results) > args.top:
    print("  ... и ещё %d страниц (--top N)" % (len(results) - args.top))

sys.exit(0)
