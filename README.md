# PHUZZ — SSRF Extension

PHUZZ is a grey-box coverage-guided fuzzer for PHP web applications (AsiaCCS 2024). This fork extends PHUZZ with **Server-Side Request Forgery (SSRF)** detection using out-of-band (OOB) callbacks and PHP runtime hooks.

---

## Table of Contents

1. [SSRF Architecture](#ssrf-architecture)
2. [Components Added](#components-added)
3. [Detection Flow](#detection-flow)
4. [Payload Variants](#payload-variants)
5. [Target Applications](#target-applications)
6. [Quick Start](#quick-start)
7. [Config Format](#config-format)
8. [Reading Results](#reading-results)
9. [Original PHUZZ](#original-phuzz)

---

## SSRF Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        phuzz-net (172.20.0.0/24)                │
│                                                                 │
│  ┌──────────────┐   HTTP + DNS   ┌──────────────────────────┐  │
│  │  phuzz-fuzzer│ ─────────────► │       phuzz-web          │  │
│  │  SSRFMutator │  X-FUZZER-COVID│  PHP + uopz + 08_ssrf.php│  │
│  │  SSRFVulnCheck◄──────────────►│  hooks: fgc/curl/socket  │  │
│  └──────────────┘   shared-tmpfs └──────────┬───────────────┘  │
│         ▲                                    │ SSRF payload      │
│         │ isfile()                           │ HTTP/DNS request  │
│         │                                    ▼                  │
│  ┌──────┴───────────────────────────────────────────────────┐   │
│  │              phuzz-oob  (172.20.0.10)                    │   │
│  │   dnsmasq: *.oob → 172.20.0.10                          │   │
│  │   Flask HTTP :8000  + HTTPS :8443                        │   │
│  │   writes: /shared-tmpfs/oob-logs/<token>.json            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  shared-tmpfs volumes                                           │
│    /shared-tmpfs/ssrf-hooks/<covID>.json   ← PHP hook writes   │
│    /shared-tmpfs/oob-logs/<token>.json     ← OOB listener writes│
│    /shared-tmpfs/ssrf-error-reports/       ← final findings     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components Added

| File | Role |
|------|------|
| `code/fuzzer/ssrf_mutator.py` | `SSRFMutator` — generates OOB URL payloads (21 IP/DNS bypass variants); `CmdInjectionSSRFMutator` — shell command payloads |
| `code/fuzzer/ssrf_vulncheck.py` | `SSRFVulnCheck` — two-stage filesystem check (hook file + OOB log) |
| `code/web/instrumentation/overrides.d/08_ssrf.php` | PHP hooks via `uopz_set_hook` for `file_get_contents`, `curl_exec`, `fsockopen`, `stream_socket_client`, `shell_exec`, WordPress wrappers, etc. |
| `code/oob/oob_listener.py` | Flask HTTP/HTTPS listener — writes `/shared-tmpfs/oob-logs/<token>.json` atomically |
| `code/oob/dnsmasq.conf` | Resolves `*.oob` wildcard → `172.20.0.10` |
| `code/oob/Dockerfile` | Builds OOB container (dnsmasq + Flask + openssl self-signed cert) |

### Integration into existing modules

**`code/fuzzer/mutator.py`** — `SingleMutator.__init__` appends `SSRFMutator`:
```python
from ssrf_mutator import SSRFMutator
self.param_mutators.append(SSRFMutator())
```

**`code/fuzzer/fuzzer.py`** — `ParamBasedVulnChecker` appends `SSRFVulnCheck`:
```python
from ssrf_vulncheck import SSRFVulnCheck
self.vuln_checkers.append(SSRFVulnCheck())
```

---

## Detection Flow

```
1. Fuzzer generates candidate with X-FUZZER-COVID: <covID> header
2. SSRFMutator injects OOB URL payload into a parameter
          e.g.  img_url=http://172.20.0.10:8000/abc123de
3. PHP executes: file_get_contents("http://172.20.0.10:8000/abc123de")
4. 08_ssrf.php hook fires → writes /shared-tmpfs/ssrf-hooks/<covID>.json
5. PHP runtime makes HTTP request to phuzz-oob:8000/abc123de
6. OOB listener receives request → writes /shared-tmpfs/oob-logs/abc123de.json
7. SSRFVulnCheck.check(candidate):
       Stage 1: ssrf-hooks/<covID>.json exists? → extract token from argument
       Stage 2: oob-logs/<token>.json exists?   → confirmed OOB callback
       → candidate.score += 1000, write ssrf-error-reports/<covID>.json
```

---

## Payload Variants

`SSRFMutator` cycles round-robin through 21 variants:

| # | Variant | Example |
|---|---------|---------|
| 0 | Plain IP | `http://172.20.0.10:8000/<token>` |
| 1 | Decimal IP | `http://2886795274:8000/<token>` |
| 2 | Hex IP | `http://0xac14000a:8000/<token>` |
| 3 | Octal IP | `http://0254.024.0.012:8000/<token>` |
| 4 | IPv6 dotted | `http://[::ffff:172.20.0.10]:8000/<token>` |
| 5 | IPv6 hex | `http://[::ffff:ac14:a]:8000/<token>` |
| 6 | URL-encoded dot | `http://172.20.0%2e10:8000/<token>` |
| 7 | Double-encoded dot | `http://172.20.0%252e10:8000/<token>` |
| 8 | Userinfo trick | `http://x@172.20.0.10:8000/<token>` |
| 9 | Reverse userinfo | `http://trusted.com@172.20.0.10:8000/<token>` |
| 10 | Mixed-case scheme | `HTTP://172.20.0.10:8000/<token>` |
| 11 | Trailing dot | `http://172.20.0.10.:8000/<token>` |
| 12 | Fragment bypass | `http://172.20.0.10:8000/<token>#trusted.com` |
| 13 | nip.io | `http://172.20.0.10.nip.io:8000/<token>` |
| 14 | sslip.io | `http://172.20.0.10.sslip.io:8000/<token>` |
| 15 | DNS wildcard (`*.oob`) | `http://<token>.oob:8000/` |
| 16 | DNS wildcard HTTPS | `https://<token>.oob:8000/` |
| 17 | DNS + userinfo | `http://x@<token>.oob:8000/` |
| 18 | DNS mixed-case | `HTTP://<token>.oob:8000/` |
| 19 | Hostname bypass | `http://oob.phuzz:8000/<token>` |
| 20 | Scheme-less HTTPS | `oob.phuzz:8443/<token>#` |

`CmdInjectionSSRFMutator` injects 10 shell command variants using `;`, `|`, `&&`, `$()`, backtick, etc. with `curl`/`wget`.

---



## Quick Start

All commands run from `d:/phuzz/code/` (or `./code/` from repo root).

### XVWA (SSRF/XSPA endpoint)

```bash
cd code/

# Build and start all services (web waits for DB, fuzzer waits for web-paths.txt)
docker compose -f docker-compose.ssrf-xvwa.yml up --build

# Stop
docker compose -f docker-compose.ssrf-xvwa.yml down -v
```


### View results (any environment)

```bash
# SSRF findings (confirmed OOB callback)
cat code/fuzzer/output/fuzzer-1/vulnerable-candidates.json | python -m json.tool

# SSRF error reports (written per candidate by SSRFVulnCheck)
ls /shared-tmpfs/ssrf-error-reports/   # inside the fuzzer container
# OR via docker:
docker exec <fuzzer-container> ls /shared-tmpfs/ssrf-error-reports/
docker exec <fuzzer-container> cat /shared-tmpfs/ssrf-error-reports/<covID>.json
```

### Follow logs in real time

```bash
# All services
docker compose -f docker-compose.ssrf-xvwa.yml logs -f

# Fuzzer only
docker compose -f docker-compose.ssrf-xvwa.yml logs -f phuzz-fuzzer

# OOB listener only
docker compose -f docker-compose.ssrf-xvwa.yml logs -f phuzz-oob
```

---

## Config Format

Fuzzer configs live in `code/fuzzer/configs/<app>/<name>.json`.

```jsonc
{
    "target": "http://web/xvwa/vulnerabilities/ssrf_xspa/index.php",
    "methods": ["POST"],
    "body_params": {
        "data": [
            { "name": "img_url", "seeds": ["http://example.com/image.jpg"] }
        ],
        "fixed": [],
        "fuzz":  [".*"],
        "weight": 1.0
    }
}
```

Add `"ssrf_only": true` to restrict mutation to SSRF payloads only (skips XSS/SQLi/etc. mutators).

### Custom OOB host

If your OOB container IP differs from `172.20.0.10`, set environment variables:

```yaml
# in docker-compose
environment:
  FUZZER_OOB_HOST: "10.0.0.5"
  FUZZER_OOB_PORT: "8000"
```

The same variable is read by `ssrf_mutator.py`, `ssrf_vulncheck.py`, and `08_ssrf.php`.

---

## Reading Results

A confirmed SSRF finding looks like:

```json
{
  "type": "SSRF",
  "candidateID": "cov-abc123",
  "payload": "http://172.20.0.10:8000/de4f9a1b",
  "url": "http://172.20.0.10:8000/de4f9a1b",
  "hookedFunction": "file_get_contents"
}
```

| Field | Meaning |
|-------|---------|
| `candidateID` | Coverage ID — matches the HTTP request that triggered the SSRF |
| `payload` | The OOB URL that was injected into the vulnerable parameter |
| `hookedFunction` | PHP function that made the outbound request |

The candidate's HTTP request (method, URL, params, headers) is stored in `code/fuzzer/output/fuzzer-<N>/vulnerable-candidates.json`.

### Shared tmpfs directories (inside containers)

| Path | Written by | Read by |
|------|-----------|---------|
| `/shared-tmpfs/ssrf-hooks/<covID>.json` | PHP (`08_ssrf.php`) | `SSRFVulnCheck` |
| `/shared-tmpfs/oob-logs/<token>.json` | OOB listener | `SSRFVulnCheck` |
| `/shared-tmpfs/ssrf-error-reports/<covID>.json` | `SSRFVulnCheck` | User / thesis analysis |
| `/shared-tmpfs/coverage-reports/<covID>.json` | PHP coverage | Fuzzer scoring |
| `/shared-tmpfs/web-paths.txt` | `web/entrypoint.sh` | Fuzzer startup check |

---

## Original PHUZZ

PHUZZ was developed by Sebastian Neef, Lorenz Kleissner & Jean-Pierre Seifert and published at AsiaCCS 2024.

```
@inproceedings{10.1145/3634737.3661137,
  author    = {Neef, Sebastian and Kleissner, Lorenz and Seifert, Jean-Pierre},
  title     = {What All the PHUZZ Is About: A Coverage-guided Fuzzer for
               Finding Vulnerabilities in PHP Web Applications},
  year      = {2024},
  doi       = {10.1145/3634737.3661137},
  booktitle = {Proceedings of the 19th ACM Asia Conference on Computer
               and Communications Security},
  series    = {ASIA CCS '24}
}
```

Original features: SQL Injection, Command Injection, Path Traversal, XXE, XSS, Open Redirect, transparent instrumentation without source modification, multi-instance parallel fuzzing, PHP 7 & 8 support.

This extension adds: **SSRF** with 21 IP/DNS bypass variants + command-injection SSRF, OOB out-of-band confirmation, PHP runtime hooks for all major HTTP/socket/shell functions, WordPress HTTP API wrappers.
