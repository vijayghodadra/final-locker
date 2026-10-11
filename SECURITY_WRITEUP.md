# Locker Security Write-up

## Executive Summary

Case Study 4 ("Locker") is a PHP and SQLite application designed for student organization secret management. An in-depth security audit of the application source code identified several security vulnerabilities and template bugs in the starter application:
1. **Predictable and replayable password-reset tokens** allowing arbitrary account takeover.
2. **Unsalted fast password hashing (SHA-256)** vulnerable to offline dictionary/rainbow table attacks.
3. **Broken HTML template form tags** (syntax artifacts causing form transmission failures).
4. **Session and CSRF vulnerabilities** in state-changing endpoints.

All genuine issues were patched, verified, and confirmed through automated unit, security, and live HTTP integration tests.

---

## Finding 1: Predictable and Replayable Password-Reset Tokens

### Severity: High (CVSS 8.8 - High)

### Affected Files and Functions
- `src/crypto.php`: `issue_reset_token()`, `consume_reset_token()`
- `public/index.php`: `/forgot` and `/reset` route handlers

### Root Cause
In the unpatched starter:
1. The reset token was deterministically computed using a known formula based solely on the user's email address and current date (e.g., `hash('sha256', $email . $date)`). Because no cryptographically random secret or secret salt was used, any attacker who knew an account's email address could precompute the valid same-day reset token.
2. The verification logic accepted a matching token even if no reset request had ever been initiated in the database.
3. Tokens were not invalidated or deleted upon successful password update, enabling replay attacks within their validity period.

### Reproduction Steps (Local Test Instance Only)
1. Launch the local application.
2. Note a target email (e.g., `maya@campus.edu`).
3. Under the vulnerable implementation, compute `hash('sha256', "maya@campus.edu" . date('Y-m-d'))`.
4. Directly POST the computed token to `/reset` with a new password, bypassing the forgot-password initiation step entirely.
5. Observe that the password was changed without the victim ever initiating a reset.

### Patch Implementation
The remediation implemented in `src/crypto.php` enforces complete token security:
```php
function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32)); // 256 bits of CSPRNG entropy
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

        // Same-day check: enforces UTC calendar day validity
        $issuedDay = gmdate('Y-m-d', strtotime((string)$row['created_at'] . ' UTC'));
        if ($issuedDay !== gmdate('Y-m-d')) {
            $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
            $pdo->commit();
            return false;
        }

        // Atomic consumption: deletes token to eliminate replay attacks
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
```
Key defenses introduced:
- **CSPRNG Generation:** Generates 32 bytes (256 bits) of entropy with `random_bytes(32)`.
- **Hashed Storage:** Only the SHA-256 digest of the token is stored in SQLite; an attacker dumping the database cannot recover valid reset tokens.
- **Timing Attack Resistance:** Compares token digests using constant-time `hash_equals()`.
- **Atomic Deletion (Single-Use):** Token is deleted within an SQLite transaction upon successful consumption, eliminating token replay.
- **Strict Expiration:** Restricts validity to the same UTC calendar day.
- **Safe Exposure Controls:** Local development displays the link only when `APP_ENV=development`. Production mode never exposes tokens in HTTP responses.

---

## Finding 2: Unsalted Fast Password Hashing

### Severity: High (CVSS 7.5 - High)

### Affected Files and Functions
- `src/crypto.php`: `hash_password()`, `verify_password()`
- `public/index.php`: POST `/login`

### Root Cause
Passwords were originally hashed using standalone, unsalted `hash('sha256', $password)`. Modern GPUs can compute tens of billions of SHA-256 hashes per second, making offline dictionary attacks trivial if the database file is compromised.

### Patch Implementation
1. Migrated password creation to PHP's standard adaptive password hashing (`password_hash($password, PASSWORD_DEFAULT)`).
2. Maintained backward compatibility for legacy hashes while ensuring seamless hash upgrading:
```php
function verify_password(string $password, string $stored): bool
{
    // Backward compatibility for legacy starter 64-char SHA-256 digests
    if (preg_match('/^[a-f0-9]{64}$/i', $stored) && hash_equals($stored, hash('sha256', $password))) {
        return true;
    }
    return password_verify($password, $stored);
}
```
3. In `public/index.php`, upon successful authentication with a legacy 64-character hex hash, the application automatically upgrades the stored hash to an adaptive bcrypt/Argon hash:
```php
if (preg_match('/^[a-f0-9]{64}$/i', (string)$user["password_hash"])) {
    set_user_password($email, $password);
}
```

---

## Finding 3: Template Form Tag Artifacts (Defect)

### Severity: Medium (Denial of Form Functionality)

### Affected Files
- `templates/layout_start.php`
- `templates/login.php`
- `templates/register.php`
- `templates/forgot.php`
- `templates/reset.php`
- `templates/new_item.php`

### Root Cause
An erroneous regular expression replacement had previously replaced the opening `<form ...>` tags with literal `\1\n` text in multiple template files. As a result, HTML forms lacked `<form>` open tags, causing form submissions and CSRF tokens to fail across browsers.

### Patch Implementation
All template files were restored with proper `<form method="post" action="...">` tags, preserving CSRF hidden inputs and flash message displays.

---

## Additional Security Defenses Verified

1. **CSRF Protection:** Every state-changing form includes an anti-CSRF token (`csrf_token()`) generated using `random_bytes(32)` and validated with `hash_equals()`.
2. **Session Security:**
   - `session.use_strict_mode = 1` prevents session adoption attacks.
   - Session identifiers are rotated upon successful login via `session_regenerate_id(true)`.
   - Session cookies are protected with `HttpOnly` and `SameSite=Lax`.
   - Conditional `Secure` attribute is enabled when HTTPS is detected.
3. **Database Security & Access Control:**
   - Parameterized queries (`PDO::prepare()`) prevent SQL injection throughout the application.
   - `PRAGMA foreign_keys = ON` enforces relational integrity.
   - Vault records are strictly isolated by session user ID (`WHERE user_id = ?`).
   - The seeded advisor account (`advisor@campus.edu`) retains exclusive ownership of confidential organizational items; members cannot view, query, or enumerate advisor items.
4. **Input Sanitization & Output Escaping:**
   - Registration strictly requires valid email syntax with `.edu` campus domains.
   - All rendered values are escaped using `e()` (`htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`).

---

## Verification and Test Results

### 1. Automated Functional and Security Test Suite (`php tests/run_tests.php`)
- **Total Tests Executed:** 44
- **Passed:** 44
- **Failed:** 0
- **Summary of Verified Controls:**
  - Syntax check across 16 PHP files: 100% PASS
  - Extension check (`pdo`, `pdo_sqlite`, `sqlite3`, `session`, `hash`, `random`, `filter`): 100% PASS
  - SQLite schema creation and table initialization: PASS
  - Demo accounts authentication (`maya@campus.edu`, `devon@campus.edu`): PASS
  - Rejection of invalid credentials: PASS
  - Adaptive password hash verification and legacy upgrade: PASS
  - Registration email validation (`.edu` enforcement, password lengths): PASS
  - Vault item creation and cross-user isolation: PASS
  - Advisor vault item confidentiality from regular members: PASS
  - Reset token 256-bit entropy and SHA-256 digest database storage: PASS
  - Rejection of invalid and prior-day expired reset tokens: PASS
  - Single-use token consumption and replay attack mitigation: PASS
  - CSRF generation and validation: PASS
  - SQLite data persistence across connection lifecycles: PASS

### 2. HTTP Server Integration Test Suite (`php tests/http_test.php`)
- **Total Endpoints Tested:** 7
- **Passed:** 13 assertions (0 failures)
- Verified endpoints: `GET /health` (200 OK, JSON `{"ok":true}`), `GET /` (200 OK), `GET /login` (200 OK), `GET /register` (200 OK), `GET /forgot` (200 OK), `GET /reset` (200 OK), `GET /random-page-123` (404 Not Found).

---

## Remaining Operational Limitations

1. **Email Delivery Provider:** The starter application is designed for local development and currently displays password reset URLs on the `/forgot` page when `APP_ENV=development`. In production (`APP_ENV=production`), this display is suppressed. A production deployment requires connecting a dedicated SMTP or transactional email API provider (e.g., PHPMailer or SendGrid) to dispatch reset links.
2. **Multi-Factor Authentication (MFA):** The current scope implements single-factor password-based authentication with vault isolation. High-security environments should consider WebAuthn or TOTP 2FA.
