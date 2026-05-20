#!/bin/bash
# elFinder 2.1.58 — init for SSRF testing (CVE-2021-32682)
echo "[elfinder] Setting up elFinder 2.1.58..."

mkdir -p /var/www/html/files
chmod 777 /var/www/html/files

# Create connector.php
# Sets X-Requested-With internally to bypass any CSRF token check
cat > /var/www/html/connector.php << 'PHPEOF'
<?php
error_reporting(0);

// Bypass elFinder CSRF check (which requires XMLHttpRequest header)
$_SERVER['HTTP_X_REQUESTED_WITH'] = 'xmlhttprequest';

include_once __DIR__ . '/php/autoload.php';

$opts = array(
    'roots' => array(
        array(
            'driver'        => 'LocalFileSystem',
            'path'          => __DIR__ . '/files/',
            'URL'           => '/files/',
            'accessControl' => null,
            'uploadAllow'   => array('all'),
            'uploadDeny'    => array('none'),
            'uploadOrder'   => array('allow', 'deny'),
        )
    )
);

$connector = new elFinderConnector(new elFinder($opts));
$connector->run();
PHPEOF

# Patch elFinderSession.php for PHP 8.2 compatibility:
# set_error_handler(array($this, 'session_start_error')) passes a protected method
# as callable — PHP 8.2 rejects this. Remove these two lines so session starts cleanly.
sed -i \
    '/set_error_handler(array(\$this, .session_start_error.), E_NOTICE | E_WARNING);/d' \
    /var/www/html/php/elFinderSession.php
sed -i \
    '/restore_error_handler();/d' \
    /var/www/html/php/elFinderSession.php


chown -R www-data:www-data /var/www/html/files /var/www/html/connector.php
echo "[elfinder] Ready."
