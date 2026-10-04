"""SAT-SA local server (stdlib only, no internet). Run: python server.py -> http://localhost:8000"""
import http.server, json, subprocess, sys, os, time, secrets, hashlib
os.chdir(os.path.dirname(os.path.abspath(__file__)))
USERS = {'examiner': hashlib.sha256(b'satsa123').hexdigest()}; TOK = {}
def log(u, a, d=''): open('audit_events.jsonl', 'a', encoding='utf-8').write(json.dumps(dict(time=time.strftime('%F %T'), user=u, action=a, detail=d)) + '\n')

class H(http.server.BaseHTTPRequestHandler):
    def out(s, code, body, ct='application/json'):
        b = body if isinstance(body, bytes) else body.encode()
        s.send_response(code); s.send_header('Content-Type', ct); s.send_header('Content-Length', str(len(b))); s.end_headers(); s.wfile.write(b)
    def user(s): return TOK.get(s.headers.get('Authorization', '').replace('Bearer ', ''))
    def do_GET(s):
        if s.path == '/': return s.out(200, open('app.html', 'rb').read(), 'text/html')
        u = s.user()
        if not u: return s.out(401, '{}')
        if s.path == '/api/data': log(u, 'view_data'); return s.out(200, open('data.json', 'rb').read())
        if s.path == '/api/events':
            ev = []
            if os.path.exists('audit_events.jsonl'):
                for l in open('audit_events.jsonl', encoding='utf-8', errors='replace'):
                    try: ev.append(json.loads(l))
                    except ValueError: pass          # skip blank/damaged lines
            return s.out(200, json.dumps(ev[-200:][::-1]))
        s.out(404, '{}')
    def do_POST(s):
        b = s.rfile.read(int(s.headers.get('Content-Length', 0))); p = s.path
        if p == '/api/login':
            j = json.loads(b)
            if USERS.get(j.get('u')) != hashlib.sha256(j.get('p', '').encode()).hexdigest():
                log(j.get('u', '?'), 'login_failed'); return s.out(401, '{}')
            t = secrets.token_hex(16); TOK[t] = j['u']; log(j['u'], 'login'); return s.out(200, json.dumps(dict(token=t)))
        u = s.user()
        if not u: return s.out(401, '{}')
        p, _, q = p.partition('?'); n = p.split('/')[-1]
        if p.startswith('/api/upload/') and n in ('alerts', 'cases', 'assets', 'entities'):
            if 'json' in q:
                import pandas as pd, io; pd.read_json(io.BytesIO(b)).to_csv(n + '.csv', index=False)
            else: open(n + '.csv', 'wb').write(b)
            log(u, 'upload', f'{n}.csv sha256={hashlib.sha256(b).hexdigest()[:12]}'); return s.out(200, '{}')
        if p == '/api/analyze':
            r = subprocess.run([sys.executable, 'satsa.py'], capture_output=True, text=True); ok = r.returncode == 0
            log(u, 'analyze', 'ok' if ok else 'failed'); return s.out(200 if ok else 500, json.dumps(dict(out=r.stdout[-400:], err=r.stderr[-400:])))
        s.out(404, '{}')
    def log_message(s, *a): pass

print('SAT-SA running at http://localhost:8000   login: examiner / satsa123')
http.server.ThreadingHTTPServer((os.environ.get('SATSA_HOST', '127.0.0.1'), 8000), H).serve_forever()
