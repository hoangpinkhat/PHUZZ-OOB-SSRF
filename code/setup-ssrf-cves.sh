#!/bin/bash
# Setup script: download all plugins and apps for CVE SSRF environments
# Run from d:/phuzz/code/ directory:
#   bash setup-ssrf-cves.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGINS_DIR="$SCRIPT_DIR/web/applications/wordpress/_plugins"
ADMINER_DIR="$SCRIPT_DIR/web/applications/adminer-4.7.8"
ELFINDER_DIR="$SCRIPT_DIR/web/applications/elfinder"
CANTO_DIR="$SCRIPT_DIR/web/applications/canto-ssrf"

mkdir -p "$PLUGINS_DIR"
mkdir -p "$ADMINER_DIR"
mkdir -p "$ELFINDER_DIR"
mkdir -p "$CANTO_DIR"

echo "=== Downloading WordPress plugins ==="

echo "[1/3] CVE-2020-24148: Import XML and RSS Feeds 2.0.1"
curl -L --progress-bar -o "$PLUGINS_DIR/import-xml-feed.2.0.1.zip" \
    "https://downloads.wordpress.org/plugin/import-xml-feed.2.0.1.zip"

echo "[2/3] CVE-2023-2249: WPForo 2.1.7"
curl -L --progress-bar -o "$PLUGINS_DIR/wpforo.2.1.7.zip" \
    "https://downloads.wordpress.org/plugin/wpforo.2.1.7.zip"

echo "[3/3] CVE-2020-28975: Canto 1.3.0"
curl -L --progress-bar -o "$CANTO_DIR/canto.1.3.0.zip" \
    "https://downloads.wordpress.org/plugin/canto.1.3.0.zip"

echo ""
echo "=== Downloading Adminer 4.7.8 ==="
echo "CVE-2021-21311: Adminer 4.7.8"
curl -L --progress-bar -o "$ADMINER_DIR/adminer.php" \
    "https://github.com/vrana/adminer/releases/download/v4.7.8/adminer-4.7.8.php"

echo ""
echo "=== Downloading elFinder ==="
echo "CVE-2021-32682: elFinder 2.1.58"
curl -L --progress-bar -o "/tmp/elfinder-2.1.58.zip" \
    "https://github.com/Studio-42/elFinder/archive/refs/tags/2.1.58.zip"
unzip -q -o "/tmp/elfinder-2.1.58.zip" -d "/tmp/elfinder-extract/"
rsync -a --exclude='init.sh' "/tmp/elfinder-extract/elFinder-2.1.58/" "$ELFINDER_DIR/"
rm -rf "/tmp/elfinder-extract" "/tmp/elfinder-2.1.58.zip"
echo "[elfinder] Extracted to $ELFINDER_DIR"

echo ""
echo "=== Downloading Skitter Slideshow ==="
echo "CVE-2022-1751: wp-skitter-slideshow (0-day, all versions)"
curl -L --progress-bar \
    "https://github.com/wp-plugins/wp-skitter-slideshow/archive/refs/heads/master.zip" \
    -o "$SCRIPT_DIR/web/applications/skitter-slideshow/wp-skitter-slideshow.zip"

echo ""
echo "=== Done! ==="
echo ""
echo "Next steps:"
echo "  # CVE-2020-24148 (Import XML RSS):"
echo "  docker compose -f docker-compose.cve-2020-24148.yml up --build"
echo "  # CVE-2023-2249 (WPForo):"
echo "  docker compose -f docker-compose.cve-2023-2249.yml up --build"
echo "  # CVE-2020-28975 (Canto SSRF):"
echo "  docker compose -f docker-compose.cve-2020-28975.yml up --build"
echo "  # CVE-2021-32682 (elFinder):"
echo "  docker compose -f docker-compose.cve-2021-32682.yml up --build"
echo "  # Pikachu SSRF lab:"
echo "  docker compose -f docker-compose.pikachu-ssrf.yml up --build"
