#!/bin/bash
# CVE-2022-1751 — wp-skitter-slideshow 0-day SSRF
# SSRF via getimagesize($_GET['image']) in image.php (no WordPress needed)

set -e
echo "[skitter] Setting up wp-skitter-slideshow SSRF lab..."

PLUGIN_ZIP="/applications/skitter-slideshow/wp-skitter-slideshow.zip"
TARGET_DIR="/var/www/html/wp-content/plugins"

mkdir -p "${TARGET_DIR}"

if [ -f "${PLUGIN_ZIP}" ]; then
    unzip -q "${PLUGIN_ZIP}" -d "${TARGET_DIR}/"
    # GitHub archive extracts as wp-skitter-slideshow-master/
    mv "${TARGET_DIR}/wp-skitter-slideshow-master" "${TARGET_DIR}/wp-skitter-slideshow"
    echo "[skitter] Plugin extracted to ${TARGET_DIR}/wp-skitter-slideshow/"
else
    echo "[skitter] ERROR: ${PLUGIN_ZIP} not found — run setup-ssrf-cves.sh first"
    exit 1
fi

chown -R www-data:www-data "${TARGET_DIR}/wp-skitter-slideshow"
echo "[skitter] Ready."
