#!/bin/bash
mkdir -p /shared-tmpfs/{coverage-reports,exception-reports,error-reports,mysql-error-reports,shell-error-reports,unserialize-error-reports,pathtraversal-error-reports,xxe-error-reports,ssrf-hooks,oob-logs}
echo "[entrypoint] Starting rsync for $APPLICATION_TYPE..."
rsync -a --exclude='*/vendor/*/test*' --exclude='*/vendor/*/doc*' \
    /applications/$APPLICATION_TYPE/ /var/www/html/
echo "[entrypoint] rsync done."
echo "[entrypoint] chown /var/www/html ..."
chown -R www-data:www-data /var/www/html/
echo "[entrypoint] chown /shared-tmpfs ..."
chown www-data:www-data /shared-tmpfs/{coverage-reports,exception-reports,error-reports,mysql-error-reports,shell-error-reports,unserialize-error-reports,pathtraversal-error-reports,xxe-error-reports,ssrf-hooks,oob-logs}
echo "[entrypoint] chown done."

if [ 0 -lt ${REQUIRES_DB} ]; then
	while ! mysqladmin ping -h"db" --silent; do
		echo "Waiting for db"
		sleep 1
	done
	echo "DB appears online!"
fi


if [ -f /var/www/html/init.sh ]; then
    chmod +x /var/www/html/init.sh
    /var/www/html/init.sh
fi

# SSRF detection: WordPress blocks requests to private IPs via WP_HTTP::block_request().
# This mu-plugin bypasses that check so curl_exec is actually called with OOB payloads,
# allowing our uopz hooks to fire.
if [ -d /var/www/html/wp-content ]; then
    mkdir -p /var/www/html/wp-content/mu-plugins
    printf '<?php\n// Fuzzer: allow WP_HTTP requests to private/internal IPs for SSRF detection\nadd_filter("http_request_host_is_external", "__return_true");\n' \
        > /var/www/html/wp-content/mu-plugins/fuzzer-ssrf.php
    chown www-data:www-data /var/www/html/wp-content/mu-plugins/fuzzer-ssrf.php
    echo "[entrypoint] fuzzer-ssrf mu-plugin installed."
fi

sed -e  "s|pcov.directory=.*|pcov.directory=${FUZZER_COVERAGE_PATH}|" -i ${PHP_INI_DIR}/php.ini

echo "[entrypoint] Building web-paths.txt..."
find /var/www/html > /shared-tmpfs/web-paths.txt
chmod 444 /shared-tmpfs/web-paths.txt
echo "[entrypoint] web-paths.txt ready. Starting Apache."

/usr/sbin/apache2ctl -D FOREGROUND
