"""Mini-crawler: discover the app's real inputs before probing.

Guessing common parameter names (q, id, search...) works, but testing the
app's actual links and forms is far more effective. The crawler walks
same-origin pages breadth-first and returns (url, [param names]) pairs that
the injection checks probe first.
"""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []  # list of (action, method, [input names])
        self._current = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._current = (a.get("action", ""),
                             a.get("method", "get").lower(), [])
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            if a.get("name"):
                self._current[2].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def _same_origin(a, b):
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def _clean(url):
    p = urlparse(url)
    return p.scheme + "://" + p.netloc + p.path


def discover(base, http, max_pages=20):
    """Crawl same-origin pages, return [(url, [params...]), ...]."""
    seen = set()
    queue = [base + "/"]
    found = []
    seen_pairs = set()
    pages = 0

    while queue and pages < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = http.get(url)
        pages += 1
        if r is None or r.status_code != 200:
            continue
        if "html" not in r.headers.get("content-type", "").lower():
            continue
        parser = _PageParser()
        try:
            parser.feed(r.text)
        except Exception:
            continue

        for href in parser.links:
            absolute = urljoin(url, href).split("#")[0]
            if not _same_origin(absolute, base):
                continue
            clean = _clean(absolute)
            query = parse_qsl(urlparse(absolute).query)
            if query:
                key = (clean, tuple(sorted(n for n, _ in query)))
                if key not in seen_pairs:
                    seen_pairs.add(key)
                    found.append((clean, [n for n, _ in query]))
            if clean not in seen and len(queue) < max_pages * 3:
                queue.append(clean)

        for action, _method, inputs in parser.forms:
            if not inputs:
                continue
            absolute = urljoin(url, action or url).split("#")[0]
            if not _same_origin(absolute, base):
                continue
            clean = _clean(absolute)
            key = (clean, tuple(sorted(inputs)))
            if key not in seen_pairs:
                seen_pairs.add(key)
                found.append((clean, inputs))

    return found
