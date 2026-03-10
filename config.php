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
$captcha_required = getenv('CAPTCHA_REQUIRED') === 'true';

// CAPTCHA Keys
$recaptcha_v2_site_key = getenv('RECAPTCHA_V2_SITE_KEY');
$recaptcha_v2_secret_key = getenv('RECAPTCHA_V2_SECRET_KEY');
$recaptcha_v3_site_key = getenv('RECAPTCHA_V3_SITE_KEY');
$recaptcha_v3_secret_key = getenv('RECAPTCHA_V3_SECRET_KEY');
$hcaptcha_site_key = getenv('HCAPTCHA_SITE_KEY');
$hcaptcha_secret_key = getenv('HCAPTCHA_SECRET_KEY');

// Verify CAPTCHA configuration if required
if ($captcha_required) {
    $has_recaptcha_v2 = !empty($recaptcha_v2_site_key) && !empty($recaptcha_v2_secret_key);
    $has_recaptcha_v3 = !empty($recaptcha_v3_site_key) && !empty($recaptcha_v3_secret_key);
    $has_hcaptcha = !empty($hcaptcha_site_key) && !empty($hcaptcha_secret_key);

    if (!$has_recaptcha_v2 && !$has_recaptcha_v3 && !$has_hcaptcha) {
        die("CAPTCHA configuration error: CAPTCHA is required but no valid keys were provided in the environment.");
    }
}

// Mailer Setup Check
if (!file_exists(__DIR__ . '/vendor/PHPMailer/src/PHPMailer.php')) {
    die("PHPMailer missing. Please run 'git clone https://github.com/PHPMailer/PHPMailer.git vendor/PHPMailer'");
}
?>