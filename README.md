# AEM Dispatcher cache leak

> A per-session endpoint, cached by the Dispatcher, served to anonymous callers.
> Reproducer, local lab, and the sanitized field evidence behind the write-up:
> **https://shoo0lin.github.io/posts/dispatcher-cache.html**

Adobe Experience Manager's author tier has an endpoint whose entire job is to answer
*"who is asking?"*:

```
GET /libs/granite/security/currentuser.json
```

The correct answer for an anonymous caller is a challenge — a redirect into the IdP, or
`401`. On the hosts in this finding, the answer was a real editor's identity, because the
Apache **Dispatcher** cached a response from an authenticated session and keyed the entry
on the path alone.

```http
HTTP/1.1 200 OK
X-Dispatcher: dispatcher1uswest2-<redacted>
X-Vhost: author
Last-Modified: Wed, 16 Oct 2024 15:34:28 GMT
Cache-control: no-cache="set-cookie"
Content-Type: application/json

{"type":"user","authorizableId":"<redacted:email>","name":"<redacted>",
 "home":"/home/users/<redacted>","isImpersonated":false}
```

No cookie. No session. One identity per host, frozen for nine to twenty-one months.

## Why the fix is not "harden AEM"

The origin was fine. Ask the same host with a query string and the cache misses, the
request reaches AEM, and AEM refuses:

| Request | Result | Where it came from |
|---|---|---|
| `GET …/currentuser.json` | `200` + identity | Dispatcher cache (HIT) |
| `GET …/currentuser.json?_=1` | `401` / `302` → IdP | Origin, correctly refusing |
| `GET …/libs/granite/security/profile.json` | SAML auto-submit page | Origin |
| `GET …/libs/granite/security/userinfo.json` | `401` | Origin |

The bug is the cache key: it does not include *who is asking*. The fix is a deny rule for
the per-session paths, not a change to the CMS.

## Run it locally (no third party involved)

There is a self-contained lab with a mock origin and a mock Dispatcher, in both the broken
and the patched configuration. Standard library only, no containers, no network egress.

```console
$ python3 lab/reproduce.py
AEM Dispatcher cache leak — local reproduction
origin: simulated AEM 6.5 author tier · dispatcher: simulated Apache/Dispatcher

mode: vulnerable (default cache rule: /libs/* cacheable)
----------------------------------------------------------------------------
[0] warm the cache as an authenticated editor
    GET /libs/granite/security/currentuser.json  (Cookie: SESSION=editor-session)
      -> 200  application/json cache=MISS   dispatcher=dispatcher1lab-000000
      identity: {"type": "user", "authorizableId": "editor@example.invalid", ...}

[1] identical URL, anonymous — no cookie, no Authorization header
    GET /libs/granite/security/currentuser.json
      -> 200  application/json cache=HIT    dispatcher=dispatcher1lab-000000
      identity: {"type": "user", "authorizableId": "editor@example.invalid", ...}

[2] control — change the cache key with a query string
    GET /libs/granite/security/currentuser.json?_=1
      -> 401  application/json cache=MISS   dispatcher=dispatcher1lab-000000

...
RESULT: VULNERABLE — the dispatcher served a per-session identity to an anonymous client
RESULT: FIXED — no cache entry is created; the origin's authentication policy applies
```

Exit code `0` means both halves held: the bug reproduced, and the patched rule closed it.
`--json` prints a machine-readable result.

The lab is deliberately small. It models the two things that matter — the cache key and
the origin's session check — and nothing else. It is not a copy of anybody's
`dispatcher.any`, and it does not try to be.

## Run it against authorised hosts

```console
$ cp examples/hosts.example.txt hosts.txt     # fill in hosts you are allowed to test
$ python3 repro.py --confirm-scope hosts.txt
```

Per host, four GETs, two seconds apart, strictly sequential:

1. the exact path, anonymous;
2. the same path with `?_=1` (forces a cache miss, shows what the origin does);
3. `profile.json` and `userinfo.json` as neighbour controls (`--no-neighbours` to skip).

Output is redacted by default — identity values are replaced, shape and booleans kept:

```
[1/1] author-<customer>-65a.adobecqms.net
  GET /libs/granite/security/currentuser.json
    200  CACHE_HIT         dispatcher=dispatcher1uswest2  last-modified=Wed, 16 Oct 2024 15:34:28 GMT
    identity: {"type": "user", "authorizableId": "<redacted:email>", "name": "<redacted>",
               "home": "/home/users/<redacted>", "isImpersonated": false}
  GET /libs/granite/security/currentuser.json?_=1
    401  AUTH_REQUIRED
  verdict: VULNERABLE
```

Safety rails are built in because these are production systems: GET only, no auth
attempts, no fuzzing, no flushing, no cache poisoning, no concurrency, and the tool
refuses to run without `--confirm-scope`.

## Severity, and the boundary

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3 Medium**.

| Capability | Status | Why |
|---|---|---|
| Read a real identity anonymously | **proven** | the whole finding |
| Enumerate other users | no | one cached identity per dispatcher node |
| Hijack a session | no | no token or cookie in the body |
| Reach content or the DAM | no | auth gate intact everywhere else |
| Escalate to admin | no | no roles or permissions exposed |

What leaks is a login identifier, a display name, an internal JCR path and
`isImpersonated: false`. That is reconnaissance-grade disclosure — useful for targeted
phishing and password spraying, not account takeover. If the same rule had caught a token
or a full profile payload, the identical misconfiguration would be an 8 or a 9. The bug is
the rule; the severity is the payload.

## Evidence and redaction

`evidence/field-2026-06-30.sanitized.json` is the sanitized field record: five hosts across
two AMS customers, four dispatcher instances, two AWS regions, cache dates from
September 2024 to September 2025. Customer names, login identifiers, display names, JCR
node IDs and dispatcher instance suffixes are replaced; the shapes are untouched.

The unredacted values are in the vendor report (Adobe HackerOne **#3813097**, triaged).
They are not published here because the caches were still serving at last verification
(2026-10-29), and a working list of anonymous identity oracles is the harm this research is
about. If remediation is confirmed, this file will be updated.

No customer data beyond the fields above was accessed. No authentication was attempted.
No cache was flushed or poisoned. The probe set was one unauthenticated GET per host and
per path, with a two-second gap.

## Layout

```
repro.py                          field probe (redacting, rate-limited, --confirm-scope)
lab/aem_lab.py                    mock AEM origin + mock Dispatcher, vulnerable|patched
lab/reproduce.py                  scripted, self-checking reproduction (exit 0 = works)
tools/render_media.py             renders the terminal screenshots and the clip
evidence/field-*.sanitized.json   sanitized field captures + provenance
examples/hosts.example.txt        format for the hosts file
```

## Disclosure status

- Reported to Adobe via HackerOne, **#3813097** — triaged.
- Published write-up: https://shoo0lin.github.io/posts/dispatcher-cache.html
- This repository intentionally contains no unredacted customer data and no working host
  list.

Not affiliated with or endorsed by Adobe. AEM and Adobe Experience Manager are trademarks
of Adobe Inc. This is independent security research against systems in an authorised
disclosure programme.

## Licence

MIT — see [LICENSE](LICENSE). The lab is for learning; the field probe is for hosts you are
authorised to test.
