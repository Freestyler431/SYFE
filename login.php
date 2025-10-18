<?php
// Shared config
require 'config.php';

// Set secure session parameters
$secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
session_set_cookie_params([
    'lifetime' => $session_cookie_lifetime * 3600,
    'path' => '/',
    'domain' => '',
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Lax'
]);
ini_set('session.gc_maxlifetime', $session_max_lifetime * 3600);

session_start();

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Database connection
$mysqli = new mysqli($mysql_host, $mysql_user, $mysql_password, $mysql_database);
if ($mysqli->connect_error) {
    error_log("MySQL connection failed: " . $mysqli->connect_error);
    header("HTTP/1.1 500 Internal Server Error");
    exit();
}

// Handle only login request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    // Rate limiting
    if (isset($_SESSION['rate_limit']) && time() < $_SESSION['rate_limit']) {
        exit("Rate limit exceeded. Please try again later.");
    }

    // Validate CSRF token
    $csrf_token = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_SPECIAL_CHARS);
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        exit("Invalid CSRF token.");
    }

    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $password = $_POST['password'] ?? '';

    // Track login attempts
    $stmt = $mysqli->prepare("UPDATE users SET login_attempts = login_attempts + 1, last_attempt = NOW() WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();

    $stmt = $mysqli->prepare("SELECT id, password, is_verified, login_attempts FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        // Check if locked out
        if ($user['login_attempts'] >= 3) {
             error_log("Account locked for user: " . $username);
            exit("Invalid credentials");
        }
        // Verify password
        if (password_verify($password, $user['password'])) {
            // Reset login attempts
            $reset_stmt = $mysqli->prepare("UPDATE users SET login_attempts = 0 WHERE id = ?");
            $reset_stmt->bind_param("i", $user['id']);
            $reset_stmt->execute();

            // Check if email verification is required
            if ($verification_method === 'email' && !$user['is_verified']) {
                exit("Please verify your email first.");
            }

            // Successful login
            session_regenerate_id(true);
            $_SESSION['user_id']    = $user['id'];
            $_SESSION['username']   = $username;
            $_SESSION['last_login'] = time();

            error_log("Successful login: " . $username);
            header("Location: index.php");
            exit();
        } else {
            $_SESSION['rate_limit'] = time() + 5;
            error_log("Failed login attempt for user: " . $username);
            exit("Invalid credentials");
        }
    } else {
        $_SESSION['rate_limit'] = time() + 5;
        error_log("Failed login attempt for non-existent user: " . $username);
        exit("Invalid credentials");
    }
}

// Security headers
header("Content-Security-Policy: default-src 'self'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

$mysqli->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Login</title>
  <link rel="stylesheet" href="css/style.css" />
</head>
<body>
  <div class="container">
    <h1>Login</h1>
    
    <form action="" method="POST">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>" />
      <input type="hidden" name="action" value="login" />

      <div class="form-field">
        <label for="login-user">Username</label>
        <input type="text" id="login-user" name="username" required />
      </div>

      <div class="form-field">
        <label for="login-pass">Password</label>
        <input type="password" id="login-pass" name="password" required />
      </div>

      <!-- reCAPTCHA/hCaptcha widget can go here if needed -->

      <input type="submit" value="Login" />
    </form>

    <div class="switch-link">
      <p>Don't have an account? <a href="register.php">Register</a></p>
    </div>
  </div>

  <script src="js/animation.js"></script>
</body>
</html>