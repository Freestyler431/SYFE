<?php
// Secure Configuration Loader
// Loads environment variables from .env file

function loadEnv($path) {
    if (!file_exists($path)) {
        return;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
            putenv(sprintf('%s=%s', $name, $value));
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
}

loadEnv(__DIR__ . '/.env');

// Database Configuration
$mysql_host = getenv('DB_HOST') ?: 'localhost';
$mysql_user = getenv('DB_USER') ?: 'root';
$mysql_password = getenv('DB_PASS') ?: '';
$mysql_database = getenv('DB_NAME') ?: 'syfe_db';

// Session Configuration
$session_max_lifetime = getenv('SESSION_LIFETIME') ?: 24;
$session_cookie_lifetime = getenv('SESSION_LIFETIME') ?: 24;
$require_login = getenv('REQUIRE_LOGIN') === 'true';
$test_mode = getenv('TEST_MODE') === 'true'; // Default to false
$server_pepper = getenv('SERVER_PEPPER') ?: 'fallback-pepper-change-me';
$reverse_proxy = getenv('REVERSE_PROXY') === 'true';

// Secure Session Initialization
function start_secure_session() {
    global $session_cookie_lifetime, $session_max_lifetime, $reverse_proxy;
    
    if (session_status() === PHP_SESSION_NONE) {
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';

        // Handle Reverse Proxy HTTPS termination
        if ($reverse_proxy && isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
            $secure = true;
        }

        session_set_cookie_params([
            'lifetime' => $session_cookie_lifetime * 3600,
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => $reverse_proxy ? 'Lax' : 'Strict' // Use Lax for reverse proxies
        ]);
        ini_set('session.gc_maxlifetime', $session_max_lifetime * 3600);
        session_start();
    }
    
    // Ensure CSRF token exists
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// SMTP Configuration
$smtp_host = getenv('SMTP_HOST');
$smtp_port = getenv('SMTP_PORT');
$smtp_username = getenv('SMTP_USER');
$smtp_password = getenv('SMTP_PASS');
$smtp_from = getenv('SMTP_FROM');

// Application Constants
$password_strength = getenv('PASSWORD_STRENGTH') ?: 'strong';
$verification_method = 'email'; // Enforced for security

// CAPTCHA Keys (Keep as placeholders/test keys per request instructions)
$recaptcha_v2_site_key = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
$recaptcha_v2_secret_key = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
$recaptcha_v3_site_key = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'; 
$recaptcha_v3_secret_key = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
$hcaptcha_site_key = '10000000-ffff-ffff-ffff-000000000001';
$hcaptcha_secret_key = '0x0000000000000000000000000000000000000000';

// Mailer Setup Check
if (!file_exists(__DIR__ . '/vendor/PHPMailer/src/PHPMailer.php')) {
    die("PHPMailer missing. Please run 'git clone https://github.com/PHPMailer/PHPMailer.git vendor/PHPMailer'");
}
?>