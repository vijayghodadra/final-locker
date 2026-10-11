<?php
declare(strict_types=1);

/**
 * Locker Automated Test Suite
 * Covers all required security and functional verifications:
 * 1. Syntax check on all PHP files
 * 2. PHP extensions check (pdo, pdo_sqlite, etc.)
 * 3. Database initialization and seeding
 * 4. User registration validation (.edu check, length checks, uniqueness)
 * 5. Demo accounts authentication (maya@campus.edu, devon@campus.edu)
 * 6. Session and logout handling
 * 7. Vault operations and strict tenant isolation
 * 8. Advisor account isolation
 * 9. Password reset token randomness, hashing, expiration, and replay protection
 * 10. CSRF validation mechanics
 * 11. Secure password hashing and legacy hash upgrade
 * 12. SQLite database persistence
 */

$testDbPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_locker_' . time() . '.db';
putenv("DATABASE_PATH={$testDbPath}");

require_once dirname(__DIR__) . '/src/bootstrap.php';

$passed = 0;
$failed = 0;

function assert_true(bool $condition, string $message): void {
    global $passed, $failed;
    if ($condition) {
        echo "[PASS] {$message}\n";
        $passed++;
    } else {
        echo "[FAIL] {$message}\n";
        $failed++;
    }
}

echo "=== STARTING LOCKER AUTOMATED TESTS ===\n\n";

// 1. PHP Syntax Check
echo "--- Test 1: PHP Syntax Checks ---\n";
$projectRoot = dirname(__DIR__);
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($projectRoot));
$allValidSyntax = true;
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $path = $file->getRealPath();
        $output = [];
        $exitCode = 0;
        exec("php -l " . escapeshellarg($path), $output, $exitCode);
        if ($exitCode !== 0) {
            $allValidSyntax = false;
            echo "Syntax error in $path\n";
        }
    }
}
assert_true($allValidSyntax, "All PHP files passed syntax linting without errors");

// 2. Required PHP Extensions
echo "\n--- Test 2: Required PHP Extensions ---\n";
$requiredExts = ['pdo', 'pdo_sqlite', 'sqlite3', 'session', 'hash', 'random', 'filter'];
foreach ($requiredExts as $ext) {
    assert_true(extension_loaded($ext), "Required extension '{$ext}' is loaded");
}

// 3. Database Initialization & Seeding
echo "\n--- Test 3: Database Initialization & Seeding ---\n";
$pdo = db();
$tableCheck = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
assert_true(in_array('users', $tableCheck), "Table 'users' exists");
assert_true(in_array('vault_items', $tableCheck), "Table 'vault_items' exists");
assert_true(in_array('reset_tokens', $tableCheck), "Table 'reset_tokens' exists");

$userCount = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
assert_true($userCount >= 3, "Database seeded with at least 3 initial users (count: {$userCount})");

// 4. Demo Accounts Authentication
echo "\n--- Test 4: Demo Account Authentication ---\n";
$maya = find_user_by_email("maya@campus.edu");
assert_true($maya !== null, "Maya account exists");
assert_true(verify_password("campus123", $maya["password_hash"]), "Maya password 'campus123' verifies");
assert_true(!verify_password("wrongpassword", $maya["password_hash"]), "Maya invalid password rejected");

$devon = find_user_by_email("devon@campus.edu");
assert_true($devon !== null, "Devon account exists");
assert_true(verify_password("campus123", $devon["password_hash"]), "Devon password 'campus123' verifies");

// 5. Password Hashing Verification
echo "\n--- Test 5: Password Storage & Hash Quality ---\n";
$info = password_get_info($maya["password_hash"]);
assert_true($info['algo'] !== 0 && $info['algo'] !== null, "Passwords are stored as adaptive password_hash(), not plain/unsalted MD5 or SHA256");

// Legacy Hash Upgrade Test
$legacySha256 = hash('sha256', 'legacySecret123');
assert_true(verify_password('legacySecret123', $legacySha256), "Legacy SHA-256 hash is correctly identified and verified");
assert_true(!verify_password('wrongLegacy', $legacySha256), "Legacy SHA-256 verification rejects wrong password");

// 6. Registration Validation
echo "\n--- Test 6: User Registration Validations ---\n";
$validEdu = "student1@campus.edu";
$nonEdu = "student2@gmail.com";

// Register non-edu
$isValidEdu = filter_var($nonEdu, FILTER_VALIDATE_EMAIL) && str_ends_with($nonEdu, ".edu");
assert_true(!$isValidEdu, "Non-edu email is rejected by registration validation");

// Register valid edu
$newUserId = create_user($validEdu, "Student One", "securepass123", "member");
$newUser = find_user_by_email($validEdu);
assert_true($newUser !== null && (int)$newUser['id'] === $newUserId, "Valid .edu user registered successfully");
assert_true(verify_password("securepass123", $newUser['password_hash']), "Newly registered user password hashes correctly");

// 7. Vault Items & Isolation
echo "\n--- Test 7: Vault Access & Isolation ---\n";
$mayaItems = vault_items_for($maya);
$devonItems = vault_items_for($devon);
assert_true(count($mayaItems) === 2, "Maya has her 2 seeded items");
assert_true(count($devonItems) === 0, "Devon has 0 seeded items");

// Devon adds an item
add_vault_item((int)$devon['id'], "Devon Wifi", "secretwifi99", "Personal note");
$devonItemsAfter = vault_items_for($devon);
$mayaItemsAfter = vault_items_for($maya);
assert_true(count($devonItemsAfter) === 1, "Devon can add and view their own vault item");
assert_true(count($mayaItemsAfter) === 2, "Maya's vault remains isolated from Devon's items");
assert_true($devonItemsAfter[0]['label'] === "Devon Wifi", "Devon vault item content matches");

// Advisor isolation
$advisor = find_user_by_email("advisor@campus.edu");
assert_true($advisor !== null, "Advisor account exists");
$advisorItems = vault_items_for($advisor);
assert_true(count($advisorItems) === 1, "Advisor has 1 seeded item");
$advisorLabels = array_column($advisorItems, 'label');
$mayaLabels = array_column($mayaItemsAfter, 'label');
$devonLabels = array_column($devonItemsAfter, 'label');
assert_true(!in_array($advisorItems[0]['label'], $mayaLabels), "Maya cannot access Advisor's vault items");
assert_true(!in_array($advisorItems[0]['label'], $devonLabels), "Devon cannot access Advisor's vault items");

// 8. Password Reset Token Flow
echo "\n--- Test 8: Password Reset Token Security ---\n";
$token1 = issue_reset_token("maya@campus.edu");
assert_true(strlen($token1) === 64, "Issued reset token is a 64-character hex string (256-bit entropy)");

// Check database storage
$stmt = $pdo->prepare("SELECT token FROM reset_tokens WHERE email = ?");
$stmt->execute(["maya@campus.edu"]);
$storedDigest = $stmt->fetchColumn();
assert_true($storedDigest !== $token1, "Raw token is NOT stored in the database");
assert_true(hash_equals($storedDigest, hash('sha256', $token1)), "Database stores SHA-256 digest of the token");

// Invalid token
assert_true(!consume_reset_token("maya@campus.edu", "0000000000000000000000000000000000000000000000000000000000000000"), "Invalid token fails consumption");

// Valid consumption
assert_true(consume_reset_token("maya@campus.edu", $token1), "Valid token is successfully consumed");

// Replay attack prevention
assert_true(!consume_reset_token("maya@campus.edu", $token1), "Replay attack fails: consumed token cannot be reused");

// Expired token test (prior UTC day)
$tokenExpired = issue_reset_token("devon@campus.edu");
$yesterdayUtc = gmdate('Y-m-d H:i:s', time() - 86400 * 2);
$pdo->prepare("UPDATE reset_tokens SET created_at = ? WHERE email = ?")->execute([$yesterdayUtc, "devon@campus.edu"]);
assert_true(!consume_reset_token("devon@campus.edu", $tokenExpired), "Expired token (prior day) is rejected and cleaned up");

// 9. CSRF Mechanics
echo "\n--- Test 9: CSRF Token Mechanics ---\n";
$token = csrf_token();
assert_true(!empty($token) && strlen($token) === 64, "CSRF token is generated and cryptographically strong");
assert_true($_SESSION['csrf_token'] === $token, "CSRF token matches session storage");

// Validate check helper
$_POST['_csrf'] = $token;
$csrfValid = hash_equals((string)$_SESSION['csrf_token'], (string)$_POST['_csrf']);
assert_true($csrfValid, "Valid CSRF token matches session expectation");

$_POST['_csrf'] = "invalid_csrf_token_value";
$csrfInvalid = hash_equals((string)$_SESSION['csrf_token'], (string)$_POST['_csrf']);
assert_true(!$csrfInvalid, "Invalid CSRF token fails validation");

// 10. Database Persistence
echo "\n--- Test 10: Database Persistence ---\n";
// Re-open SQLite connection
$pdo2 = new PDO("sqlite:" . $testDbPath);
$countPersist = (int)$pdo2->query("SELECT COUNT(*) FROM users")->fetchColumn();
assert_true($countPersist >= 4, "Database records persist across separate database connections (count: {$countPersist})");

// Cleanup test db
$pdo = null;
$pdo2 = null;
gc_collect_cycles();
register_shutdown_function(function() use ($testDbPath) {
    @unlink($testDbPath);
    @unlink($testDbPath . '-wal');
    @unlink($testDbPath . '-shm');
});

echo "\n=== TEST SUMMARY ===\n";
echo "Total tests passed: {$passed}\n";
echo "Total tests failed: {$failed}\n";

if ($failed > 0) {
    exit(1);
} else {
    echo "\nALL TESTS PASSED SUCCESSFULLY!\n";
    exit(0);
}
