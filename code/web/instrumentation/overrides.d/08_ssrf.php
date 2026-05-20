<?php

##########################################################################################
#                              SSRF instrumentation hooks                                #
##########################################################################################
#                                                                                        #
#  Hooks (via uopz_set_hook):                                                            #
#    Network / HTTP:                                                                     #
#      • file_get_contents                                                               #
#      • fopen                                                                           #
#      • readfile                                                                        #
#      • file                                                                            #
#      • get_headers                                                                     #
#      • get_meta_tags                                                                   #
#      • getimagesize                                                                    #
#                                                                                        #
#    cURL:                                                                               #
#      • curl_exec                                                                       #
#      • curl_multi_exec                                                                 #
#                                                                                        #
#    Sockets:                                                                            #
#      • fsockopen                                                                       #
#      • pfsockopen                                                                      #
#      • stream_socket_client                                                            #
#                                                                                        #
#    Shell execution (Command Injection -> SSRF):                                        #
#      • shell_exec                                                                      #
#      • system                                                                          #
#      • exec                                                                            #
#      • passthru                                                                        #
#      • popen                                                                           #
#                                                                                        #
#    WordPress wrappers:                                                                 #
#      • wp_remote_get                                                                   #
#      • wp_remote_post                                                                  #
#      • wp_remote_request                                                               #
#      • wp_safe_remote_get                                                              #
#      • wp_safe_remote_post                                                             #
#                                                                                        #
#  Trigger condition: argument contains the OOB IP "172.20.0.10"                        #
#                                                                                        #
#  On trigger: write JSON log to                                                         #
#    /shared-tmpfs/ssrf-hooks/<candidateID>.json                                        #
#                                                                                        #
#  uopz_set_hook() = purely observational, original function runs normally.             #
#                                                                                        #
##########################################################################################

define('__FUZZER__SSRF_HOOKS_PATH', '/shared-tmpfs/ssrf-hooks/');
define('__FUZZER__OOB_HOST', getenv('FUZZER_OOB_HOST') ?: '172.20.0.10');

if (!is_dir(__FUZZER__SSRF_HOOKS_PATH)) {
    mkdir(__FUZZER__SSRF_HOOKS_PATH, 0777, true);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Write a single SSRF hook log for the current candidate.
 * First-write-wins: once the file exists for this candidateID it is not
 * overwritten so we capture the earliest trigger per request.
 */
function __fuzzer__ssrf_log(string $function, string $argument): void
{
    $path = __FUZZER__SSRF_HOOKS_PATH . __FUZZER__COVID . '.json';
    if (file_exists($path)) {
        return;
    }

    $entry = json_encode([
        'function'  => $function,
        'argument'  => $argument,
        'timestamp' => time(),
    ]);

    file_put_contents($path, $entry);
    chmod($path, 0777);
}

/**
 * Return true when $value contains any known OOB identifier.
 * Covers all SSRFMutator payload variants:
 *   plain/userinfo/fragment  → "172.20.0.10"
 *   decimal                  → "2886795274"
 *   hex                      → "0xac14000a"
 *   octal                    → "0254.024.0.012"
 *   IPv6 mapped (dotted)     → "::ffff:172.20.0.10"
 *   IPv6 mapped (hex)        → "::ffff:ac14"
 *   DNS *.oob                → ".oob:"  or  ".oob/"
 *   nip.io                   → "172.20.0.10.nip.io"
 *   sslip.io                 → "172.20.0.10.sslip.io"
 *   trailing-dot IP          → "172.20.0.10."
 */
function __fuzzer__ssrf_is_oob(string $value): bool
{
    static $needles = null;
    if ($needles === null) {
        $oob = __FUZZER__OOB_HOST;
        // decimal/hex/octal representations are pre-computed for the default IP;
        // they are only used by SSRFMutator bypass variants — if a custom OOB IP
        // is set those variants are skipped anyway, so keeping the defaults is safe.
        $needles = [
            $oob,
            '2886795274',
        '0xac14000a',
        '0254.024.0.012',
        '::ffff:ac14',
        '.oob:',
        '.oob/',
        '.nip.io',
        '.sslip.io',
        'oob.phuzz',
        ];
    }
    $lower = strtolower($value);
    foreach ($needles as $needle) {
        if (strpos($lower, $needle) !== false) {
            return true;
        }
    }
    return false;
}

// ===========================================================================
// NETWORK / HTTP FUNCTIONS
// ===========================================================================

// ---------------------------------------------------------------------------
// file_get_contents
// ---------------------------------------------------------------------------
uopz_set_hook(
    'file_get_contents',
    function (string $filename) {
        if (__fuzzer__ssrf_is_oob($filename)) {
            __fuzzer__ssrf_log('file_get_contents', $filename);
        }
    }
);

// ---------------------------------------------------------------------------
// fopen — opens file or URL: fopen("http://...", "r")
// ---------------------------------------------------------------------------
uopz_set_hook(
    'fopen',
    function (string $filename) {
        if (__fuzzer__ssrf_is_oob($filename)) {
            __fuzzer__ssrf_log('fopen', $filename);
        }
    }
);

// ---------------------------------------------------------------------------
// readfile — reads and outputs a file/URL: readfile("http://...")
// ---------------------------------------------------------------------------
uopz_set_hook(
    'readfile',
    function (string $filename) {
        if (__fuzzer__ssrf_is_oob($filename)) {
            __fuzzer__ssrf_log('readfile', $filename);
        }
    }
);

// ---------------------------------------------------------------------------
// file — reads file/URL into array: file("http://...")
// ---------------------------------------------------------------------------
uopz_set_hook(
    'file',
    function (string $filename) {
        if (__fuzzer__ssrf_is_oob($filename)) {
            __fuzzer__ssrf_log('file', $filename);
        }
    }
);

// ---------------------------------------------------------------------------
// get_headers — fetches HTTP headers: get_headers("http://...")
// ---------------------------------------------------------------------------
uopz_set_hook(
    'get_headers',
    function (string $url) {
        if (__fuzzer__ssrf_is_oob($url)) {
            __fuzzer__ssrf_log('get_headers', $url);
        }
    }
);

// ---------------------------------------------------------------------------
// get_meta_tags — fetches <meta> tags from URL
// ---------------------------------------------------------------------------
uopz_set_hook(
    'get_meta_tags',
    function (string $filename) {
        if (__fuzzer__ssrf_is_oob($filename)) {
            __fuzzer__ssrf_log('get_meta_tags', $filename);
        }
    }
);

// ---------------------------------------------------------------------------
// getimagesize — fetches image info from URL: getimagesize("http://...")
// ---------------------------------------------------------------------------
uopz_set_hook(
    'getimagesize',
    function (string $filename) {
        if (__fuzzer__ssrf_is_oob($filename)) {
            __fuzzer__ssrf_log('getimagesize', $filename);
        }
    }
);

// ===========================================================================
// CURL
// ===========================================================================

// ---------------------------------------------------------------------------
// curl_exec — curl_getinfo() captures URL before execution
// ---------------------------------------------------------------------------
uopz_set_hook(
    'curl_exec',
    function ($ch) {
        $info = curl_getinfo($ch);
        $url  = $info['url'] ?? '';

        if ($url !== '' && __fuzzer__ssrf_is_oob($url)) {
            __fuzzer__ssrf_log('curl_exec', $url);
        }
    }
);

// ---------------------------------------------------------------------------
// curl_multi_exec — iterate all handles in the multi handle
// ---------------------------------------------------------------------------
uopz_set_hook(
    'curl_multi_exec',
    function ($mh) {
        // curl_multi_info_read not available before exec, use curl_multi_getcontent
        // Walk known handles via curl_multi_getcontent workaround: not trivially
        // available. Best-effort: check via curl_getinfo on each handle if
        // the multi handle exposes them. Since it does not, we hook
        // curl_setopt instead for multi scenarios (see below).
    }
);

// ---------------------------------------------------------------------------
// curl_setopt — capture CURLOPT_URL at set time (covers curl_multi_exec)
// ---------------------------------------------------------------------------
uopz_set_hook(
    'curl_setopt',
    function ($ch, int $option, $value) {
        // CURLOPT_URL = 10002
        if ($option === CURLOPT_URL && is_string($value) && __fuzzer__ssrf_is_oob($value)) {
            __fuzzer__ssrf_log('curl_setopt(CURLOPT_URL)', $value);
        }
    }
);

// ===========================================================================
// SOCKETS
// ===========================================================================

// ---------------------------------------------------------------------------
// fsockopen
// ---------------------------------------------------------------------------
uopz_set_hook(
    'fsockopen',
    function (string $hostname) {
        if (__fuzzer__ssrf_is_oob($hostname)) {
            __fuzzer__ssrf_log('fsockopen', $hostname);
        }
    }
);

// ---------------------------------------------------------------------------
// pfsockopen — persistent version of fsockopen
// ---------------------------------------------------------------------------
uopz_set_hook(
    'pfsockopen',
    function (string $hostname) {
        if (__fuzzer__ssrf_is_oob($hostname)) {
            __fuzzer__ssrf_log('pfsockopen', $hostname);
        }
    }
);

// ---------------------------------------------------------------------------
// stream_socket_client — "tcp://host:port" or "ssl://host:port"
// ---------------------------------------------------------------------------
uopz_set_hook(
    'stream_socket_client',
    function (string $address) {
        if (__fuzzer__ssrf_is_oob($address)) {
            __fuzzer__ssrf_log('stream_socket_client', $address);
        }
    }
);

// ===========================================================================
// SHELL EXECUTION (Command Injection -> SSRF)
// Detects when a shell command containing an OOB identifier is executed.
// Covers: shell_exec, system, exec, passthru, popen
// ===========================================================================

uopz_set_hook(
    'shell_exec',
    function (string $cmd) {
        if (__fuzzer__ssrf_is_oob($cmd)) {
            __fuzzer__ssrf_log('shell_exec', $cmd);
        }
    }
);

uopz_set_hook(
    'system',
    function (string $cmd) {
        if (__fuzzer__ssrf_is_oob($cmd)) {
            __fuzzer__ssrf_log('system', $cmd);
        }
    }
);

uopz_set_hook(
    'exec',
    function (string $cmd) {
        if (__fuzzer__ssrf_is_oob($cmd)) {
            __fuzzer__ssrf_log('exec', $cmd);
        }
    }
);

uopz_set_hook(
    'passthru',
    function (string $cmd) {
        if (__fuzzer__ssrf_is_oob($cmd)) {
            __fuzzer__ssrf_log('passthru', $cmd);
        }
    }
);

uopz_set_hook(
    'popen',
    function (string $cmd) {
        if (__fuzzer__ssrf_is_oob($cmd)) {
            __fuzzer__ssrf_log('popen', $cmd);
        }
    }
);

// ===========================================================================
// WORDPRESS HTTP WRAPPERS
// (only registered if WordPress is loaded)
// ===========================================================================

if (function_exists('wp_remote_get')) {

    uopz_set_hook(
        'wp_remote_get',
        function (string $url) {
            if (__fuzzer__ssrf_is_oob($url)) {
                __fuzzer__ssrf_log('wp_remote_get', $url);
            }
        }
    );

    uopz_set_hook(
        'wp_remote_post',
        function (string $url) {
            if (__fuzzer__ssrf_is_oob($url)) {
                __fuzzer__ssrf_log('wp_remote_post', $url);
            }
        }
    );

    uopz_set_hook(
        'wp_remote_request',
        function (string $url) {
            if (__fuzzer__ssrf_is_oob($url)) {
                __fuzzer__ssrf_log('wp_remote_request', $url);
            }
        }
    );

    uopz_set_hook(
        'wp_safe_remote_get',
        function (string $url) {
            if (__fuzzer__ssrf_is_oob($url)) {
                __fuzzer__ssrf_log('wp_safe_remote_get', $url);
            }
        }
    );

    uopz_set_hook(
        'wp_safe_remote_post',
        function (string $url) {
            if (__fuzzer__ssrf_is_oob($url)) {
                __fuzzer__ssrf_log('wp_safe_remote_post', $url);
            }
        }
    );

}
