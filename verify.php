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

require 'utils.php';

// Check if verification is pending
if (!isset($_SESSION['pending_verification']) || !isset($_SESSION['pending_email'])) {
    header("Location: login.php");
    exit();
}

// Database connection
$mysqli = new mysqli($mysql_host, $mysql_user, $mysql_password, $mysql_database);
if ($mysqli->connect_error) {
    error_log("MySQL connection failed: " . $mysqli->connect_error);
    header("HTTP/1.1 500 Internal Server Error");
    exit();
}

$error_message = '';
$success_message = '';

// Handle verification submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'verify') {
     if (isset($_SESSION['rate_limit']) && time() < $_SESSION['rate_limit']) {
        exit("Rate limit exceeded. Please try again later.");
    }

    // Validate CSRF token
    $csrf_token = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_SPECIAL_CHARS);
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        $error_message = "Invalid CSRF token.";
    } else {
        $email = $_SESSION['pending_email'];
        $otp = filter_input(INPUT_POST, 'otp', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

        // Check if OTP is valid
        $stmt = $mysqli->prepare("SELECT id, verification_token, otp_expiry FROM users WHERE email = ? AND is_verified = 0");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            $current_time = time();
            
            // Check if OTP matches and is not expired
            if ($user['otp_expiry'] < $current_time) {
                $_SESSION['rate_limit'] = time() + 5;
                $error_message = "Verification code has expired. Please request a new one.";
            } elseif (!$otp_case_sensitive) {
                // Case-insensitive comparison if configured
                if (strtolower($otp) !== strtolower($user['verification_token'])) {
                    $_SESSION['rate_limit'] = time() + 5;
                    $error_message = "Invalid verification code.";
                } else {
                    // Mark user as verified
                    $update = $mysqli->prepare("UPDATE users SET is_verified = 1, verification_token = '' WHERE id = ?");
                    $update->bind_param("i", $user['id']);
                    
                    if ($update->execute()) {
                        $_SESSION['user_id'] = $user['id'];
                        unset($_SESSION['pending_verification']);
                        unset($_SESSION['pending_email']);
                        $success_message = "Email verified successfully!";
                        
                        // Redirect after short delay
                        header("refresh:2;url=index.php");
                    } else {
                        $error_message = "Verification failed. Please try again.";
                    }
                }
            } else {
                // Case-sensitive comparison
                if ($otp !== $user['verification_token']) {
                    $error_message = "Invalid verification code.";
                } else {
                    // Mark user as verified
                    $update = $mysqli->prepare("UPDATE users SET is_verified = 1, verification_token = '' WHERE id = ?");
                    $update->bind_param("i", $user['id']);
                    
                    if ($update->execute()) {
                        $_SESSION['user_id'] = $user['id'];
                        unset($_SESSION['pending_verification']);
                        unset($_SESSION['pending_email']);
                        $success_message = "Email verified successfully!";
                        
                        // Redirect after short delay
                        header("refresh:2;url=dashboard.php");
                    } else {
                        $error_message = "Verification failed. Please try again.";
                    }
                }
            }
        } else {
            $error_message = "Invalid verification attempt.";
        }
    }
}

// Handle resend verification code
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'resend') {
    // Validate CSRF token
    $csrf_token = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_SPECIAL_CHARS);
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        $error_message = "Invalid CSRF token.";
    } else {
        $email = $_SESSION['pending_email'];
        $verification_token = generate_otp();
        $otp_expiry = time() + ($otp_expiry_minutes * 60);
        
        // Update the verification token and expiry
        $stmt = $mysqli->prepare("UPDATE users SET verification_token = ?, otp_expiry = ? WHERE email = ?");
        $stmt->bind_param("sis", $verification_token, $otp_expiry, $email);
        
        if ($stmt->execute() && send_verification_email($email, $verification_token)) {
            $success_message = "Verification code has been resent to your email.";
        } else {
            $error_message = "Failed to resend verification code.";
        }
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
  <title>Verify Email</title>
  <link rel="stylesheet" href="css/style.css" />
</head>
<body>
  <div class="container">
    <h1>Email Verification</h1>
    
    <?php if ($error_message): ?>
      <div class="alert alert-danger"><?php echo htmlspecialchars($error_message); ?></div>
    <?php endif; ?>
    
    <?php if ($success_message): ?>
      <div class="alert alert-success"><?php echo htmlspecialchars($success_message); ?></div>
    <?php else: ?>
      <p>Please enter the verification code sent to <?php echo htmlspecialchars($_SESSION['pending_email']); ?></p>

      <form action="" method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>" />
        <input type="hidden" name="action" value="verify" />

        <div class="form-field">
          <label for="otp">Verification Code</label>
          <input type="text" id="otp" name="otp" required autofocus />
        </div>

        <input type="submit" value="Verify Email" />
      </form>

      <form action="" method="POST" class="resend-form">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>" />
        <input type="hidden" name="action" value="resend" />
        <p>Didn't receive the code?</p>
        <input type="submit" value="Resend Verification Code" class="secondary-button" />
      </form>
    <?php endif; ?>

  </div>

  <script src="js/animation.js"></script>
</body>
</html>