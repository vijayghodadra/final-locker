# Locker

Locker is a secure PHP + SQLite application for a student organization (University of Delaware Case Study 4). Organization members can securely store credentials, door codes, and notes in an authenticated personal vault. Vault queries and mutations are strictly scoped to the authenticated user's ID.

---

## Prerequisites

- **Operating System:** Windows 10/11, macOS, or Linux.
- **PHP Version:** PHP 8.2 or PHP 8.3 (tested with PHP 8.3.33).
- **SQLite:** SQLite 3 (bundled with PHP PDO SQLite).

### Required PHP Extensions
The following PHP extensions must be enabled:
- `pdo`
- `pdo_sqlite`
- `sqlite3`
- `session`
- `hash`
- `random`
- `filter`
- `openssl` (recommended)
- `mbstring` (recommended)

---

## Windows Setup Instructions

### 1. Install PHP via WinGet (Recommended)
Open PowerShell and install PHP:
```powershell
winget install --id PHP.PHP.8.3 --accept-source-agreements --accept-package-agreements
```

### 2. Configure `php.ini`
Locate your PHP installation directory (typically in `%LOCALAPPDATA%\Microsoft\WinGet\Packages\PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe`):
1. Copy `php.ini-development` to `php.ini`.
2. Open `php.ini` and ensure the following directives are enabled (uncomment by removing the leading `;`):
   ```ini
   extension_dir = "ext"
   extension=pdo_sqlite
   extension=sqlite3
   extension=openssl
   extension=mbstring
   ```

### 3. Verify PHP Installation and Extensions
In a new PowerShell terminal, run:
```powershell
php -v
php -m
```
Verify that `pdo_sqlite` and `sqlite3` are present in the list of modules.

---

## Running the Application

### Exact Command to Start Locally
From the project root (`C:\Users\vijay\Desktop\Locker-patched\Locker`):

```powershell
php -S 127.0.0.1:3000 -t public public/router.php
```

### Local Application URL
Open your browser and navigate to:
- **`http://localhost:3000`** or **`http://127.0.0.1:3000`**

To stop the server, press `Ctrl+C` in the terminal.

---

## Database Initialization Details

- **Database Engine:** SQLite 3 with Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and foreign key constraints enabled (`PRAGMA foreign_keys = ON`).
- **Database Path:** Defaults to `data/locker.db`. The application automatically creates the directory and file if it does not exist on the first request. You can override the location via the `DATABASE_PATH` environment variable.
- **Auto-Seeding:** On first run, the database schema (`users`, `vault_items`, `reset_tokens`) is created and seeded with demo accounts and vault items.
- **Persistence:** Database records persist across server restarts in `data/locker.db`.

---

## Demo Accounts

The database comes pre-seeded with the following accounts for local evaluation:

| Email | Password | Role | Notes |
|---|---|---|---|
| `maya@campus.edu` | `campus123` | member | Pre-seeded with 2 personal vault items (Shop door code, Instagram login). |
| `devon@campus.edu` | `campus123` | member | Empty vault shelf. Use to test adding items and verifying isolation. |
| `advisor@campus.edu` | *(Protected)* | advisor | Seeded advisor account storing card emergency PIN. No demo password is disclosed. |

---

## Automated Testing

The project includes automated test suites covering syntax, security controls, and end-to-end HTTP integration:

### 1. Functional & Security Unit Tests
```powershell
php tests/run_tests.php
```
Tests:
- Syntax linting across all PHP files.
- Required PHP extension verification.
- Database initialization and schema verification.
- User registration validation (enforcing `.edu` domain, display name, and password length).
- Authentication with demo credentials.
- Password hashing verification (adaptive `password_hash()` and legacy SHA-256 upgrade).
- Vault isolation (ensuring users and advisors cannot access each other's secrets).
- Password reset token security (256-bit entropy, SHA-256 digest storage, same-day expiration, and replay defense).
- CSRF token generation and validation.
- SQLite database persistence across connections.

### 2. HTTP Server Integration Tests
```powershell
php tests/http_test.php
```
Tests live HTTP response codes (200, 404), JSON output (`/health`), and form rendering across all endpoints.

---

## Security Features & Defenses

1. **Password Storage:** Uses PHP `password_hash()` (`PASSWORD_DEFAULT` / Bcrypt) instead of fast unsalted hashes. Legacy seeded accounts are safely verified and upgraded upon login.
2. **Password Reset Tokens:** Uses cryptographically secure random 256-bit tokens (`random_bytes(32)`). Only the SHA-256 digest is stored in the database. Tokens expire at the end of the UTC calendar day and are atomically consumed/deleted upon use to prevent replay attacks.
3. **Session Hardening:** Configured with `session.use_strict_mode = 1`, session regeneration on login, `HttpOnly` cookie flags, `SameSite=Lax`, and conditional `Secure` flag over HTTPS.
4. **CSRF Protection:** State-changing requests (`POST /login`, `POST /register`, `POST /logout`, `POST /forgot`, `POST /reset`, `POST /items`) validate cryptographic CSRF tokens using `hash_equals()`.
5. **SQL Injection Defense:** All queries use parameterized PDO prepared statements (`$stmt->prepare()` and `$stmt->execute()`).
6. **Vault Isolation:** Vault items are strictly queried by `user_id = :session_user_id`. No endpoint permits direct item access or cross-account access.
7. **Email Validation:** Requires standard email format and restricted campus `.edu` domain on registration.
8. **HTML Escaping:** All user-controlled output is escaped using `e()` (`htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`).

---

## Troubleshooting

- **`php` is not recognized:**
  Ensure the PHP installation path is in your `PATH` environment variable. In PowerShell, restart your shell or run:
  ```powershell
  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
  ```
- **Driver not found (`could not find driver`):**
  Ensure `extension=pdo_sqlite` and `extension=sqlite3` are uncommented in your `php.ini`. Run `php -m` to verify `pdo_sqlite` appears in the list.
- **Port 3000 already in use:**
  If port 3000 is occupied, run on another port, for example:
  ```powershell
  php -S 127.0.0.1:3001 -t public public/router.php
  ```
- **Database permission issues:**
  Ensure the `data/` folder has write permissions for your current user account.
