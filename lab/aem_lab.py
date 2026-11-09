#!/usr/bin/env python3
"""
aem_lab.py — a small, honest reproduction of the AEM Dispatcher cache bug.

Two servers run in one process:

  origin      (default :18091)  A stand-in for an AEM author tier. It requires a
                                session cookie and returns the session's identity
                                for /libs/granite/security/currentuser.json.

  dispatcher  (default :18090)  A stand-in for Apache + Dispatcher. It caches GET
                                200 responses keyed by (path, query string) and
                                never includes the session in that key.

The dispatcher has two modes:

  --mode vulnerable   cache /libs/granite/security/currentuser.json like any other
                      path. The first authenticated response becomes the response
                      for everyone — the field bug.

  --mode patched      deny caching for /libs/granite/security/* and pass those
                      requests straight to the origin. This is the fix described
                      in the write-up.

Usage (manual poking):

    python3 lab/aem_lab.py --mode vulnerable
    curl -i http://127.0.0.1:18090/libs/granite/security/currentuser.json
    # warm the cache as a session holder in another shell/step:
    curl -i -H 'Cookie: SESSION=editor-session' \
         http://127.0.0.1:18090/libs/granite/security/currentuser.json
    curl -i http://127.0.0.1:18090/libs/granite/security/currentuser.json

The scripted version — the one used for the screenshots and the clip — is
lab/reproduce.py. No third-party dependencies.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CURRENT_USER = "/libs/granite/security/currentuser.json"
PROFILE = "/libs/granite/security/profile.json"
USERINFO = "/libs/granite/security/userinfo.json"

# One simulated editor. Fake values, obviously.
SESSIONS = {
    "editor-session": {
        "type": "user",
        "authorizableId": "editor@example.invalid",
        "name": "Editor Example",
        "home": "/home/users/e/example-node",
        "isImpersonated": False,
    }
}

SAML_PAGE = (
    "<!doctype html><html><body>"
    "<form method=\"post\" action=\"https://idp.example.invalid/saml\">"
    "<input type=\"hidden\" name=\"SAMLRequest\" value=\"fVNdk9owEP01zLQ3BmwM2ARy...\">"
    "</form><script>document.forms[0].submit()</script></body></html>"
)


class Origin(BaseHTTPRequestHandler):
    """AEM author tier: session required, identity returned per session."""

    protocol_version = "HTTP/1.1"
    server_version = "AEM/6.5"

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        cookie = self.headers.get("Cookie", "")

        if path == CURRENT_USER:
            session = _session_from_cookie(cookie)
            if session is None:
                return self._send(401, "application/json",
                                  json.dumps({"status": 401, "error": "unauthorized"}).encode())
            return self._send(200, "application/json",
                              json.dumps(SESSIONS[session]).encode(),
                              extra={"Cache-Control": 'no-cache="set-cookie"'})

        if path == PROFILE:
            if _session_from_cookie(cookie) is None:
                return self._send(200, "text/html", SAML_PAGE.encode())
            return self._send(200, "application/json", b'{"profile":"example"}')

        if path == USERINFO:
            return self._send(401, "application/json", b'{"status":401,"error":"unauthorized"}')

        return self._send(404, "text/plain", b"Not Found")

    def _send(self, status, ctype, body, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Dispatcher(BaseHTTPRequestHandler):
    """Apache + Dispatcher: caches by (path, query) and ignores the session."""

    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4 (Dispatcher)"

    origin_base = "http://127.0.0.1:18091"
    mode = "vulnerable"
    cache: dict[tuple[str, str], dict] = {}
    instance = "dispatcher1lab-000000"
    lock = threading.Lock()

    def do_GET(self):  # noqa: N802
        path, _, query = self.path.partition("?")
        denied = self.mode == "patched" and path.startswith("/libs/granite/security/")
        key = (path, query)

        if denied:
            return self._proxy(key, cacheable=False, cache_state="BYPASS")

        with self.lock:
            entry = self.cache.get(key)
        if entry is not None:
            return self._serve(entry, cache_state="HIT")

        return self._proxy(key, cacheable=path.startswith("/libs/"), cache_state="MISS")

    def _proxy(self, key, cacheable, cache_state):
        req = urllib.request.Request(
            self.origin_base + self.path,
            headers={
                "Cookie": self.headers.get("Cookie", ""),
                "Accept": self.headers.get("Accept", "*/*"),
                "User-Agent": self.headers.get("User-Agent", "lab"),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                status, ctype, body = r.status, r.headers.get("Content-Type", ""), r.read()
                last_modified = r.headers.get("Last-Modified")
        except urllib.error.HTTPError as e:
            status, ctype, body = e.code, e.headers.get("Content-Type", ""), e.read()
            last_modified = e.headers.get("Last-Modified")

        if cacheable and status == 200:
            with self.lock:
                self.cache[key] = {
                    "status": status,
                    "ctype": ctype,
                    "body": body,
                    "stored": time.time(),
                    "last_modified": last_modified or _httpdate(time.time()),
                }
            cache_state = cache_state if cache_state == "BYPASS" else "MISS"

        self._write(status, ctype, body, cache_state, last_modified)

    def _serve(self, entry, cache_state):
        self._write(entry["status"], entry["ctype"], entry["body"], cache_state,
                    entry["last_modified"], age=int(time.time() - entry["stored"]))

    def _write(self, status, ctype, body, state, last_modified=None, age=0):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Dispatcher", self.instance)
        self.send_header("X-Vhost", "author")
        self.send_header("X-Dispatcher-Cache", state)
        if last_modified:
            self.send_header("Last-Modified", last_modified)
        self.send_header("Age", str(age))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def _session_from_cookie(cookie: str):
    for part in cookie.split(";"):
        name, _, value = part.strip().partition("=")
        if name == "SESSION" and value in SESSIONS:
            return value
    return None


def _httpdate(ts: float) -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(ts))


def start(mode: str = "vulnerable", host: str = "127.0.0.1",
          dispatcher_port: int = 18090, origin_port: int = 18091):
    """Start origin + dispatcher on background threads. Returns (threads, servers)."""
    Dispatcher.mode = mode
    Dispatcher.cache.clear()
    Dispatcher.origin_base = f"http://{host}:{origin_port}"

    origin = ThreadingHTTPServer((host, origin_port), Origin)
    dispatcher = ThreadingHTTPServer((host, dispatcher_port), Dispatcher)
    threads = []
    for srv in (origin, dispatcher):
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        threads.append(t)
    return threads, (dispatcher, origin)


def stop(servers):
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("vulnerable", "patched"), default="vulnerable")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--dispatcher-port", type=int, default=18090)
    ap.add_argument("--origin-port", type=int, default=18091)
    args = ap.parse_args()

    _, servers = start(args.mode, args.host, args.dispatcher_port, args.origin_port)
    print(f"dispatcher http://{args.host}:{args.dispatcher_port}  (mode={args.mode})")
    print(f"origin     http://{args.host}:{args.origin_port}  (simulated AEM author)")
    print("ctrl-c to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop(servers)


if __name__ == "__main__":
    main()
