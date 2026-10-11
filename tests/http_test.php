<?php
declare(strict_types=1);

/**
 * End-to-end HTTP integration test
 * Launches the PHP dev server, tests HTTP endpoints, then terminates it.
 */

$port = 3000;
$serverCmd = "php -S 127.0.0.1:{$port} -t public public/router.php";

$descriptors = [
    0 => ["pipe", "r"],
    1 => ["pipe", "w"],
    2 => ["pipe", "w"]
];

$process = proc_open($serverCmd, $descriptors, $pipes, dirname(__DIR__));

if (!is_resource($process)) {
    echo "[FAIL] Could not start PHP built-in server\n";
    exit(1);
}

// Give the server 1 second to start
usleep(1000000);

function http_get(string $url, array &$responseHeaders = []): array {
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'ignore_errors' => true,
            'timeout' => 5
        ]
    ]);
    $body = @file_get_contents($url, false, $context);
    $responseHeaders = $http_response_header ?? [];
    return [$body, $responseHeaders];
}

$passed = 0;
$failed = 0;

function check(bool $cond, string $msg): void {
    global $passed, $failed;
    if ($cond) {
        echo "[PASS] {$msg}\n";
        $passed++;
    } else {
        echo "[FAIL] {$msg}\n";
        $failed++;
    }
}

try {
    echo "--- HTTP Integration Tests on http://127.0.0.1:3000 ---\n";

    // 1. /health
    [$healthBody, $hHeaders] = http_get("http://127.0.0.1:{$port}/health");
    check(str_contains($hHeaders[0] ?? '', '200'), "GET /health returns HTTP 200");
    check(str_contains((string)$healthBody, '{"ok":true}'), "GET /health returns ok:true JSON");

    // 2. /
    [$homeBody, $homeHeaders] = http_get("http://127.0.0.1:{$port}/");
    check(str_contains($homeHeaders[0] ?? '', '200'), "GET / returns HTTP 200");
    check(str_contains((string)$homeBody, "Locker"), "GET / renders Locker home");

    // 3. /login
    [$loginBody, $loginHeaders] = http_get("http://127.0.0.1:{$port}/login");
    check(str_contains($loginHeaders[0] ?? '', '200'), "GET /login returns HTTP 200");
    check(str_contains((string)$loginBody, '<form method="post" action="/login">'), "GET /login renders valid form tag");

    // 4. /register
    [$regBody, $regHeaders] = http_get("http://127.0.0.1:{$port}/register");
    check(str_contains($regHeaders[0] ?? '', '200'), "GET /register returns HTTP 200");
    check(str_contains((string)$regBody, '<form method="post" action="/register">'), "GET /register renders valid form tag");

    // 5. /forgot
    [$forgotBody, $forgotHeaders] = http_get("http://127.0.0.1:{$port}/forgot");
    check(str_contains($forgotHeaders[0] ?? '', '200'), "GET /forgot returns HTTP 200");
    check(str_contains((string)$forgotBody, '<form method="post" action="/forgot">'), "GET /forgot renders valid form tag");

    // 6. /reset
    [$resetBody, $resetHeaders] = http_get("http://127.0.0.1:{$port}/reset");
    check(str_contains($resetHeaders[0] ?? '', '200'), "GET /reset returns HTTP 200");
    check(str_contains((string)$resetBody, '<form method="post" action="/reset">'), "GET /reset renders valid form tag");

    // 7. Non-existent page 404
    [$notFoundBody, $nfHeaders] = http_get("http://127.0.0.1:{$port}/random-page-123");
    check(str_contains($nfHeaders[0] ?? '', '404'), "GET /random-page-123 returns HTTP 404");

} finally {
    // Terminate the process cleanly
    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) fclose($pipe);
    }
    proc_terminate($process);
    proc_close($process);
}

echo "\nHTTP Integration Tests: {$passed} passed, {$failed} failed.\n";
if ($failed > 0) exit(1);
