#!/bin/bash
set -e

echo "[mutillidae] Extracting Mutillidae II..."

ZIP="/applications/mutillidae/mutillidae.zip"
if [ ! -f "$ZIP" ]; then
    echo "[mutillidae] ERROR: $ZIP not found"
    exit 1
fi

unzip -q "$ZIP" -d /tmp/
# GitHub archive extracts to mutillidae-master/src/
cp -r /tmp/mutillidae-main/src/. /var/www/html/
rm -rf /tmp/mutillidae-main
echo "[mutillidae] Source extracted."

# Patch DB config: change host 127.0.0.1 → db
DB_CONFIG=$(find /var/www/html/includes -name "database-config.inc" 2>/dev/null | head -1)
if [ -n "$DB_CONFIG" ]; then
    sed -i "s/127\.0\.0\.1/db/g" "$DB_CONFIG"
    echo "[mutillidae] DB config patched: $(grep -m1 'host\|server\|db_server' "$DB_CONFIG" | head -1)"
else
    echo "[mutillidae] WARNING: database-config.inc not found, searching..."
    find /var/www/html -name "*.inc" -o -name "*.php" | xargs grep -l "127.0.0.1" 2>/dev/null | head -3
fi

chown -R www-data:www-data /var/www/html/
echo "[mutillidae] Done."
