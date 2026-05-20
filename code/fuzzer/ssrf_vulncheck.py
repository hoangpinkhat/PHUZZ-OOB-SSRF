import json
import os
from urllib.parse import urlparse

from vulncheck import VulnCheck

SSRF_HOOKS_DIR = "/shared-tmpfs/ssrf-hooks"
OOB_LOGS_DIR   = "/shared-tmpfs/oob-logs"
OOB_HOST       = os.environ.get("FUZZER_OOB_HOST", "172.20.0.10")
OOB_DOMAIN     = "oob"          # wildcard *.oob → OOB_HOST via dnsmasq
OOB_HOSTNAME   = "oob.phuzz"    # plain hostname → OOB_HOST via extra_hosts (HTTP + HTTPS)

SSRF_CRITICAL_SCORE = 1000


class SSRFVulnCheck(VulnCheck):
    """
    Two-stage SSRF detector (filesystem-only, non-blocking).

    Stage 1: PHP hook wrote /shared-tmpfs/ssrf-hooks/<candidateID>.json
    Stage 2: OOB listener wrote /shared-tmpfs/oob-logs/<token>.json

    Token is now in the URL path: http://172.20.0.10:8000/<token>
    """

    NAME = "SSRF"

    def __init__(self, ssrf_errors_folder="/shared-tmpfs/ssrf-error-reports"):
        self.ssrf_errors_folder = ssrf_errors_folder
        os.makedirs(self.ssrf_errors_folder, exist_ok=True)

    def check(self, candidate) -> bool:
        hook_file = os.path.join(SSRF_HOOKS_DIR, f"{candidate.coverage_id}.json")
        if not os.path.isfile(hook_file):
            return False

        try:
            with open(hook_file) as fh:
                hook_data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return False

        argument = hook_data.get("argument", "")
        token = self._extract_token(argument)
        if not token:
            return False

        oob_file = os.path.join(OOB_LOGS_DIR, f"{token}.json")
        if not os.path.isfile(oob_file):
            return False

        candidate.score += SSRF_CRITICAL_SCORE
        candidate.ssrf_report = {
            "type":           "SSRF",
            "candidateID":    candidate.coverage_id,
            "payload":        argument,
            "url":            argument,
            "hookedFunction": hook_data.get("function", ""),
        }
        
        # Write SSRF error report
        report_file = os.path.join(self.ssrf_errors_folder, f"{candidate.coverage_id}.json")
        with open(report_file, "w") as f:
            json.dump(candidate.ssrf_report, f, indent=2)
        
        return True

    @staticmethod
    def _extract_token(url: str) -> "str | None":
        """
        Extract token from all payload formats:
          IP-based:       http://172.20.0.10:8000/<token>        → token from path
          DNS-based:      http://<token>.oob:8000/               → token from subdomain
          nip.io/sslip:   http://172.20.0.10.nip.io:8000/<token> → token from path
          trailing dot:   http://172.20.0.10.:8000/<token>       → strip dot, token from path
          fragment:       http://172.20.0.10:8000/<token>#...    → strip fragment
          cmd injection:  ping -c 4 127.0.0.1; curl http://172.20.0.10:8000/<token>
                          → extract embedded URL first, then parse it
        """
        import re
        # If the argument is a shell command (contains OOB IP but doesn't start
        # with a URL scheme), extract the embedded http(s):// URL first.
        lower = url.lower()
        if not lower.startswith(("http://", "https://", "ftp://")) and (
            OOB_HOST in lower or OOB_HOSTNAME in lower or f".{OOB_DOMAIN}:" in lower
        ):
            # Find the first http(s):// URL containing the OOB identifier
            m = re.search(r'https?://\S+', lower)
            if m:
                url = m.group(0)
            else:
                # scheme-less or other formats — try original path
                pass

        try:
            parsed = urlparse(url.lower())
            hostname = (parsed.hostname or "").rstrip(".")  # strip trailing dot

            # IP-based: plain, decimal, hex, octal, IPv6, userinfo, fragment, trailing-dot
            # Use only first path segment — some apps (e.g. Adminer) append their own path.
            if hostname == OOB_HOST:
                token = parsed.path.strip("/").split("/")[0].split("#")[0]
                return token if token else None

            # DNS-based: token is leftmost label of *.oob
            if hostname.endswith(f".{OOB_DOMAIN}"):
                token = hostname.split(".")[0]
                return token if token else None

            # nip.io / sslip.io: OOB_HOST is prefix of hostname, token in path
            if hostname.startswith(f"{OOB_HOST}."):
                token = parsed.path.strip("/").split("/")[0].split("#")[0]
                return token if token else None

            # Hostname-based bypass (oob.phuzz via extra_hosts): token in path
            if hostname == OOB_HOSTNAME:
                token = parsed.path.strip("/").split("/")[0].split("#")[0]
                return token if token else None

        except Exception:
            pass
        return None
