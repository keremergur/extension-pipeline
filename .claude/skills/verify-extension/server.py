#!/usr/bin/env python3
"""Mock attacker server for the request categories. Logs every incoming request with the
browser-generated Sec-Fetch-Site header (unforgeable, on the forbidden-header list):
  Sec-Fetch-Site: none  => NO web page initiated it -> the EXTENSION made the request.
  (a page-initiated fetch to this server would read 'cross-site')

Run:  python server.py [logfile]     (default logfile: ./_verify_server.log)
Listens on 127.0.0.1:3000. GET returns a JSON body with a recognizable token so 2way
findings can prove the response body flowed back to the page.
"""
import http.server, socketserver, datetime, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "_verify_server.log"


def _write(line: str):
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        _write(f"[{ts}] {self.command} {self.path} | Sec-Fetch-Site={self.headers.get('Sec-Fetch-Site')} "
               f"Origin={self.headers.get('Origin')} Referer={self.headers.get('Referer')}")

    def do_GET(self):
        self._log()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'{"token":"SERVER_SECRET_9182","status":"ok"}')

    def do_POST(self):
        ln = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(ln) if ln else b''
        self._log(); _write("   body: " + repr(body[:200]))
        self.send_response(200); self.send_header('Access-Control-Allow-Origin', '*'); self.end_headers()
        self.wfile.write(b'{"token":"SERVER_SECRET_9182"}')

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    open(LOG, "w", encoding="utf-8").close()  # truncate at start
    with socketserver.TCPServer(("127.0.0.1", 3000), H) as s:
        _write("mock server on http://127.0.0.1:3000 (log: %s)" % LOG)
        s.serve_forever()
