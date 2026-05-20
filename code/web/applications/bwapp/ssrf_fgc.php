<?php
// bWAPP SSRF via file_get_contents — phuzz SSRF lab endpoint
// GET /ssrf_fgc.php?url=<payload>

$url = isset($_GET['url']) ? $_GET['url'] : '';

if ($url === '') {
    http_response_code(400);
    echo json_encode(['error' => 'url param required']);
    exit;
}

$data = file_get_contents($url);
echo $data !== false ? $data : json_encode(['error' => 'fetch failed']);
