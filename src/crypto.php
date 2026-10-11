<?php
declare(strict_types=1);

// Passwords use PHP's adaptive password hashing. Reset tokens are random, single-use,
// stored only as a SHA-256 digest, and valid only on the UTC calendar day they were issued.

function hash_password(string $password): string
{
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password(string $password, string $stored): bool
{
    // Backward-compatible verification for databases created by the original starter.
    // Successful legacy logins are upgraded to password_hash() by the login route.
    if (preg_match('/^[a-f0-9]{64}$/i', $stored) && hash_equals($stored, hash('sha256', $password))) {
        return true;
    }
    return password_verify($password, $stored);
}

function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32));
    $digest = hash('sha256', $token);
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $digest]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $token = strtolower(trim($token));
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return false;
    }

    $pdo = db();
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
        $stmt->execute([$email]);
        $row = $stmt->fetch();

        if (!$row || !hash_equals((string)$row['token'], hash('sha256', $token))) {
            $pdo->rollBack();
            return false;
        }

        // "Same-day" means the UTC date on which the token was issued.
        $issuedDay = gmdate('Y-m-d', strtotime((string)$row['created_at'] . ' UTC'));
        if ($issuedDay !== gmdate('Y-m-d')) {
            $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
            $pdo->commit();
            return false;
        }

        // Consume before returning success so a token cannot be replayed.
        $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}
