#!/usr/bin/env python3
"""
OOB (Out-of-Band) HTTP listener for PHUZZ SSRF detection.

Responsibilities
----------------
* Accept every inbound HTTP request on port 8000 (any method, any path).
* Extract the SSRF token from the URL path, e.g.:
      GET /abc123de HTTP/1.1  →  token = "abc123de"
* Persist a JSON log entry to:
      /shared-tmpfs/oob-logs/<token>.json
  (first-write-wins so the file is created once per token)

The log file is written atomically using a write-then-rename pattern so that
the VulnChecker in the fuzzer container never reads a partially-written file.

Performance notes
-----------------
* Flask runs with threaded=True so concurrent SSRF callbacks do not block.
* os.path.exists() guards prevent redundant writes (no file-lock needed on
  tmpfs because the check+write is fast enough to avoid races in practice;
  duplicate log entries only affect diagnostics, not correctness).
* The fuzzer's VulnChecker reads /shared-tmpfs/oob-logs/<token>.json via a
  plain os.path.isfile() check — no polling, no sockets, no blocking.
"""

import json
import os
import ssl
import tempfile
import threading
import time

from flask import Flask, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OOB_LOGS_DIR  = "/shared-tmpfs/oob-logs"
OOB_PORT      = 8000
OOB_PORT_TLS  = 8443
CERT_FILE     = "/app/oob.crt"
KEY_FILE      = "/app/oob.key"

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
os.makedirs(OOB_LOGS_DIR, mode=0o777, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_token(path: str, host: str = "") -> "str | None":
    """
    Extract the SSRF token from the URL path or Host header subdomain.

    Path-based (direct IP / nip.io / sslip.io payloads):
        GET /abc123de          → 'abc123de'
        GET /abc123de/extra    → 'abc123de'

    Subdomain-based (*.oob domain payloads):
        Host: abc123de.oob:8000, path=/  → 'abc123de'

    Examples
    --------
    >>> extract_token("/abc123de")
    'abc123de'
    >>> extract_token("/", "abc123de.oob:8000")
    'abc123de'
    >>> extract_token("/")
    None
    """
    first = path.strip("/").split("/")[0]
    if first:
        return first
    # Fallback: extract token from *.oob subdomain in Host header
    if host:
        hostname = host.split(":")[0]  # strip port
        if hostname.endswith(".oob"):
            subdomain = hostname.split(".")[0]
            return subdomain if subdomain else None
    return None


def write_log(token: str, remote_ip: str) -> None:
    """
    Atomically write /shared-tmpfs/oob-logs/<token>.json.

    Uses write-to-temp + os.rename so the VulnChecker never reads an
    incomplete file.  First-write-wins: if the file already exists the
    function returns immediately.
    """
    log_path = os.path.join(OOB_LOGS_DIR, f"{token}.json")
    if os.path.exists(log_path):
        return

    entry = json.dumps({
        "token":     token,
        "ip":        remote_ip,
        "timestamp": int(time.time()),
    })

    # Write to a temp file in the same directory, then rename atomically
    fd, tmp_path = tempfile.mkstemp(dir=OOB_LOGS_DIR, prefix=f".tmp_{token}_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(entry)
        os.chmod(tmp_path, 0o777)
        os.rename(tmp_path, log_path)
    except Exception:
        # Clean up temp file on failure; do not surface errors to the caller
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Route — catch all
# ---------------------------------------------------------------------------

@app.route(
    "/",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
@app.route(
    "/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
def catch_all(path: str):
    token = extract_token(request.path, request.host or "")

    if token:
        write_log(token, request.remote_addr or "unknown")

    # Always respond 200 so the PHP application does not raise a network error
    # that could mask the SSRF from the instrumentation hooks.
    return "", 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _run_https() -> None:
    """HTTPS listener on OOB_PORT_TLS with self-signed cert (SSL verification disabled on client side)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.check_hostname = False
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        app.run(host="0.0.0.0", port=OOB_PORT_TLS, ssl_context=ctx, threaded=True)
    except Exception as exc:
        print(f"[oob] HTTPS listener failed: {exc}", flush=True)


if __name__ == "__main__":
    threading.Thread(target=_run_https, daemon=True).start()
    app.run(host="0.0.0.0", port=OOB_PORT, threaded=True)
