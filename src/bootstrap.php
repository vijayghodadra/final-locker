<?php
declare(strict_types=1);

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
ini_set('session.use_strict_mode', '1');
session_start();

require __DIR__ . "/db.php";
require __DIR__ . "/crypto.php";
require __DIR__ . "/auth.php";
require __DIR__ . "/vault.php";

init_db();
seed();

function render(string $view, array $data = [], int $status = 200): void
{
    http_response_code($status);
    extract($data, EXTR_SKIP);
    $currentUser = current_user();
    $csrfToken = csrf_token();
    require dirname(__DIR__) . "/templates/layout_start.php";
    require dirname(__DIR__) . "/templates/{$view}.php";
    require dirname(__DIR__) . "/templates/layout_end.php";
    exit;
}

function redirect(string $to): void
{
    header("Location: " . $to);
    exit;
}

function json_out(array $data): void
{
    header("Content-Type: application/json");
    echo json_encode($data);
    exit;
}

function e(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['csrf_token'];
}

function require_valid_csrf(): void
{
    $submitted = (string)($_POST['_csrf'] ?? '');
    $expected = (string)($_SESSION['csrf_token'] ?? '');
    if ($expected === '' || $submitted === '' || !hash_equals($expected, $submitted)) {
        http_response_code(403);
        render('error', ['title' => 'Request expired', 'message' => 'Please go back, refresh the page, and try again.'], 403);
    }
}
