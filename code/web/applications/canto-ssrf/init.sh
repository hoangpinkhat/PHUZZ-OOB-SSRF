#!/bin/bash
# Canto 1.3.0 — CVE-2020-28975/76/77/78
# Extracts plugin files so the SSRF endpoints are directly accessible
# without WordPress bootstrap (pure PHP files, no WP required).

set -e
echo "[canto] Setting up Canto 1.3.0 SSRF lab..."

PLUGIN_ZIP="/applications/canto-ssrf/canto.1.3.0.zip"
TARGET_DIR="/var/www/html/wp-content/plugins"

mkdir -p "${TARGET_DIR}"

if [ -f "${PLUGIN_ZIP}" ]; then
    unzip -q "${PLUGIN_ZIP}" -d "${TARGET_DIR}/"
    echo "[canto] Plugin extracted to ${TARGET_DIR}/canto/"
else
    echo "[canto] ERROR: ${PLUGIN_ZIP} not found — run setup-ssrf-cves.sh first"
    exit 1
fi

chown -R www-data:www-data "${TARGET_DIR}/canto"
echo "[canto] Ready."
