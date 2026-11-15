"""Deterministic sites for the real Chromium scanner; no API mocking."""
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == '/tree.json':
            categories = 'Email Address Username People Search Engines Public Records Telephone Numbers IP & MAC Address'
            payload = json.dumps({'name': categories, 'type': 'folder', 'children': [
                {'name': 'Fixture match', 'type': 'url', 'url': 'http://fixtures:9000/search/match'},
                {'name': 'Fixture empty', 'type': 'url', 'url': 'http://fixtures:9000/search/empty'},
                {'name': 'Fixture blocked', 'type': 'url', 'url': 'http://fixtures:9000/search/blocked'},
            ]}).encode()
            content_type = 'application/json'
        else:
            query = parse_qs(path.query).get('q', [''])[0]
            if path.path.endswith('/blocked'):
                self.send_response(403)
                self.end_headers()
                return
            body = html.escape(query) if path.path.endswith('/match') else 'Nothing to see here.'
            payload = f'<html><head><title>Fixture directory</title></head><body><article>{body}</article></body></html>'.encode()
            if path.path.endswith('/echo'):
                q = html.escape(query)
                payload = f'<html><head><title>{q} - Search</title><meta name="description" content="{q}"></head><body><form>Search for {q}<input value="{q}"></form><nav><a href="?q={q}">{q}</a></nav><article>No records available.</article><div hidden>{q}</div><script>const query = "{q}"</script></body></html>'.encode()
            content_type = 'text/html; charset=utf-8'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


ThreadingHTTPServer(('0.0.0.0', 9000), Handler).serve_forever()
