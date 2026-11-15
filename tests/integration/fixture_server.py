"""Deterministic sites for the real Chromium scanner; no API mocking."""
import html
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path in ('/sherlock.json', '/sherlock-slow.json'):
            manifest = {}
            for kind in (('slow',) if path.path == '/sherlock-slow.json' else ('found', 'missing', 'blocked')):
                manifest[f'Fixture Sherlock {kind}'] = {
                    'urlMain': 'http://fixtures:9000',
                    'url': f'http://fixtures:9000/sherlock/{kind}/{{}}',
                    'username_claimed': 'sample_user',
                    'errorType': 'message', 'errorMsg': 'USER_NOT_FOUND',
                }
            if path.path == '/sherlock.json':
                for name in ('7Cups', 'F3.cool', 'Houzz'):
                    manifest[name] = dict(manifest['Fixture Sherlock found'])
            payload = json.dumps(manifest).encode()
            content_type = 'application/json'
        elif path.path.startswith('/sherlock/'):
            if '/slow/' in path.path:
                time.sleep(8)
            if '/missing/' in path.path:
                payload = b'USER_NOT_FOUND'
            elif '/blocked/' in path.path:
                payload = b'<span id="challenge-error-text">Blocked</span>'
            else:
                payload = b'<h1>Public user profile</h1>'
            content_type = 'text/html'
        elif path.path == '/tree.json':
            categories = 'Email Address Username People Search Engines Public Records Telephone Numbers IP & MAC Address'
            payload = json.dumps({'name': categories, 'type': 'folder', 'children': [
                {'name': 'Fixture match', 'type': 'url', 'url': 'http://fixtures:9000/search/match'},
                {'name': 'Fixture empty', 'type': 'url', 'url': 'http://fixtures:9000/search/empty'},
                {'name': 'Fixture slow', 'type': 'url', 'url': 'http://fixtures:9000/search/slow'},
                {'name': 'Fixture blocked', 'type': 'url', 'url': 'http://fixtures:9000/search/blocked'},
                {'name': 'Repository-only tool', 'type': 'url', 'url': 'https://github.com/example/tool'},
            ]}).encode()
            content_type = 'application/json'
        else:
            query = parse_qs(path.query).get('q', [''])[0]
            if path.path.endswith('/blocked'):
                self.send_response(403)
                self.end_headers()
                return
            if path.path.endswith('/slow'):
                time.sleep(8)
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
