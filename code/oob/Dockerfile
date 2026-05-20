# Reuse the same pinned python image as phuzz-fuzzer — already cached, no
# Docker Hub credential lookup needed for unpinned tags.
FROM python:3@sha256:2e376990a11f1c1e03796d08db0e99c36eadb4bb6491372b227f1e53c3482914

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dnsmasq supervisor openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Self-signed cert for HTTPS OOB listener (port 8443)
RUN openssl req -x509 -newkey rsa:2048 -keyout /app/oob.key -out /app/oob.crt \
        -days 3650 -nodes -subj '/CN=oob.phuzz'

COPY oob_listener.py   .
COPY dnsmasq.conf      /etc/dnsmasq.conf
COPY supervisord.conf  /etc/supervisor/conf.d/supervisord.conf

# Port 53/udp   – DNS (resolves *.oob for the web container)
# Port 8000/tcp  – HTTP OOB callback endpoint
# Port 8443/tcp  – HTTPS OOB callback endpoint (for apps that force https://)
EXPOSE 53/udp 8000/tcp 8443/tcp

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
