"""
Minimal HTML form parsing for driving the IdP's login, consent, and device
approval pages the way a browser would (read the hidden fields + CSRF token,
resubmit them). Kept dependency-free (stdlib ``html.parser``) so the suite has
no BeautifulSoup/lxml requirement.
"""

from html.parser import HTMLParser


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_form = False
        self.action = None
        self.method = "post"
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._in_form = True
            self.action = attrs.get("action") or self.action
            self.method = (attrs.get("method") or "post").lower()
        elif tag in ("input", "select", "textarea") and self._in_form:
            name = attrs.get("name")
            if name:
                self.fields[name] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


def parse_form(html):
    """Return ``(action, fields)`` for the first ``<form>`` in ``html``.

    ``action`` is ``None`` when the form posts back to the same URL.
    """
    parser = _FormParser()
    parser.feed(html)
    return parser.action, parser.fields
