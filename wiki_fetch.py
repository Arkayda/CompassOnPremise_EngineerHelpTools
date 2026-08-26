#!/usr/bin/env python3

import sys

sys.dont_write_bytecode = True

# Выкачивание статической базы знаний Compass (VitePress) в локальный markdown-дамп.
# Читает sitemap.xml, скачивает каждую страницу, вытаскивает содержимое <main>
# и сохраняет в файлы с сохранением структуры URL. Рядом кладёт index.json
# (файл -> канонический url, заголовок, время загрузки) — его использует wiki_search.py.
#
# Без зависимостей: python 3.8+ (urllib + html.parser из stdlib).

import ssl
import time
import json
import argparse
import urllib.request
from pathlib import Path
from html.parser import HTMLParser
from datetime import datetime

DEFAULT_SITEMAP = "https://wiki.service.sel.apitest.team/sitemap.xml"
DEFAULT_HOST = "wiki.service.sel.apitest.team"
DEFAULT_OUT = str(Path.home() / "compass-wiki")

parser = argparse.ArgumentParser(
    description="Выкачивание базы знаний Compass (VitePress) в локальный дамп для поиска/LLM.",
    usage="python3 wiki_fetch.py [--sitemap URL] [--host HOST] [--out DIR] [--delay SEC]",
    epilog="Примеры:\n"
           "  python3 wiki_fetch.py                                  # дефолты: apitest.team -> ~/compass-wiki\n"
           "  python3 wiki_fetch.py --out /tmp/wiki --delay 0.1\n"
           "\n"
           "Повторный запуск обновляет только изменившиеся страницы (по длине/дате не проверяем — качает все).",
)
parser.add_argument("--sitemap", required=False, default=DEFAULT_SITEMAP, type=str,
                    help="URL sitemap.xml")
parser.add_argument("--host", required=False, default=DEFAULT_HOST, type=str,
                    help="Хост, с которого качать (url из sitemap переписывается на него)")
parser.add_argument("--out", required=False, default=DEFAULT_OUT, type=str,
                    help="Каталог дампа (по умолчанию ~/compass-wiki)")
parser.add_argument("--delay", required=False, default=0.2, type=float,
                    help="Пауза между страницами, секунд")
parser.add_argument("--limit", required=False, default=0, type=int,
                    help="Ограничить число страниц (0 = без ограничения; для пробы)")
args = parser.parse_args()

SSL_CONTEXT = ssl.create_default_context()


# получить текст url (с одним повтором при сетевой ошибке)
def fetch_text(url, timeout=30):
    last_error = None
    for attempt in range(2):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "compass-wiki-fetch/1.0"})
            with urllib.request.urlopen(request, timeout=timeout, context=SSL_CONTEXT) as response:
                return response.read().decode("utf-8", "ignore")
        except Exception as e:
            last_error = e
            time.sleep(1)
    raise last_error


# url из sitemap -> фактический url с нужным хостом
def rewrite_host(url):
    # https://getcompass.wiki/path -> https://<host>/path
    parts = url.split("/", 3)
    if len(parts) >= 4:
        return "%s//%s/%s" % (parts[0], args.host, parts[3])
    return url


# url -> путь файла в дампе (/content/a/b -> a/b.md)
def url_to_file_path(url):
    path = url.split("://", 1)[-1].split("/", 1)[-1]  # без схемы и хоста
    path = path.strip("/").rstrip("/")
    if not path:
        path = "index"
    if not path.endswith(".md"):
        path += ".md"
    return path


# парсер: текст <main> с переводами строк между блоками; заголовок h1 отдельно
class MainTextExtractor(HTMLParser):
    BLOCK_TAGS = {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
                  "pre", "blockquote", "table", "ul", "ol", "br", "hr", "section", "article"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_main = 0
        self.skip_depth = 0
        self.title = ""
        self.title_done = False
        self.chunks = []
        self.preformatted = 0

    def handle_starttag(self, tag, attrs):
        if tag == "main":
            self.in_main += 1
            return
        if not self.in_main:
            return
        if tag in ("script", "style", "nav", "footer", "header"):
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "pre":
            self.preformatted += 1
        if tag in self.BLOCK_TAGS:
            self.chunks.append("\n")
        if tag in ("h1", "h2", "h3", "h4") and not (tag == "h1" and self.title_done):
            self.chunks.append("\n" + "#" * int(tag[1]) + " ")

    def handle_endtag(self, tag):
        if tag == "main":
            self.in_main -= 1
            return
        if not self.in_main:
            return
        if tag in ("script", "style", "nav", "footer", "header"):
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if self.skip_depth:
            return
        if tag == "pre":
            self.preformatted = max(0, self.preformatted - 1)
        if tag in self.BLOCK_TAGS:
            self.chunks.append("\n")

    def handle_data(self, data):
        if not self.in_main or self.skip_depth:
            return
        if not self.title and data.strip() and not self.chunks:
            pass  # заголовок достаём отдельным проходом
        self.chunks.append(data)


# превратить html в текст: main -> строки, h1-h6 -> #-заголовки
def html_to_text(html):
    extractor = MainTextExtractor()
    extractor.feed(html)

    text = "".join(extractor.chunks)
    # склеиваем разбитые переносы, убираем тройные+
    lines = [line.rstrip() for line in text.splitlines()]
    cleaned = []
    blank = 0
    for line in lines:
        if not line.strip():
            blank += 1
            if blank > 1:
                continue
        else:
            blank = 0
        cleaned.append(line)

    body = "\n".join(cleaned).strip()

    # заголовок: первый непустой # или первый h1 из html
    title = ""
    for line in body.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    return body, title


def main():
    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Читаем sitemap: %s" % args.sitemap)
    sitemap_xml = fetch_text(args.sitemap)

    urls = []
    for token in sitemap_xml.split("<loc>"):
        if "</loc>" in token:
            urls.append(token.split("</loc>")[0].strip())

    if not urls:
        print("В sitemap не найдено url")
        sys.exit(1)

    if args.limit:
        urls = urls[:args.limit]

    print("Страниц к загрузке: %d -> %s" % (len(urls), out_dir))

    index_path = out_dir / "index.json"
    index = {}
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except Exception:
            index = {}

    ok_count, fail_count = 0, 0
    for number, canonical_url in enumerate(urls, start=1):
        file_path = out_dir / url_to_file_path(canonical_url)
        actual_url = rewrite_host(canonical_url)

        try:
            html = fetch_text(actual_url)
            body, title = html_to_text(html)
            if not body.strip():
                raise ValueError("пустой <main> (страница отдаётся без контента?)")

            file_path.parent.mkdir(parents=True, exist_ok=True)
            header = ["<!-- source: %s -->" % canonical_url, "<!-- fetched: %s -->" % datetime.now().isoformat(timespec="seconds"), ""]
            file_path.write_text("\n".join(header) + body + "\n", encoding="utf-8")

            index[str(file_path.relative_to(out_dir))] = {
                "url": canonical_url,
                "title": title or file_path.stem,
                "fetched_at": datetime.now().isoformat(timespec="seconds"),
            }
            ok_count += 1
        except Exception as e:
            fail_count += 1
            print("  [FAIL] %s: %s" % (canonical_url, e))

        if number % 20 == 0 or number == len(urls):
            print("  %d/%d (ошибок: %d)" % (number, len(urls), fail_count))

        time.sleep(args.delay)

    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    print("")
    print("Готово: скачано %d, ошибок %d" % (ok_count, fail_count))
    print("Дамп:   %s" % out_dir)
    print("Индекс: %s (%d записей)" % (index_path, len(index)))
    print("")
    print("Поиск по дампу: python3 wiki_search.py <слова>")


if __name__ == "__main__":
    main()
