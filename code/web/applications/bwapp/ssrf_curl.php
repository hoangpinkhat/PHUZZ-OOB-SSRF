<?php
// bWAPP SSRF via curl_exec — phuzz SSRF lab endpoint
// GET /ssrf_curl.php?url=<payload>

$url = isset($_GET['url']) ? $_GET['url'] : '';

if ($url === '') {
    http_response_code(400);
    echo json_encode(['error' => 'url param required']);
    exit;
}

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
$response = curl_exec($ch);
curl_close($ch);

echo $response !== false ? $response : json_encode(['error' => 'curl failed']);
