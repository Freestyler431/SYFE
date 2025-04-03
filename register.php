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

// Password strength helper
function isPasswordStrongEnough($password) {
    global $password_strength, $password_custom_length;
    switch ($password_strength) {
        case 'weak':
            return strlen($password) >= 6;
        case 'medium':
            return strlen($password) >= 8;
        case 'strong':
            return strlen($password) >= 12 &&
                   preg_match('/[A-Z]/', $password) &&
                   preg_match('/[a-z]/', $password) &&
                   preg_match('/\d/', $password) &&
                   preg_match('/[^A-Za-z0-9]/', $password);
        case 'custom':
            return strlen($password) >= $password_custom_length;
        default:
            return strlen($password) >= 6;
    }
}

// OTP generation function
function generate_otp() {
    global $otp_length, $otp_type, $otp_case_sensitive;
    $characters = match ($otp_type) {
        'alpha'        => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'alphanumeric' => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        default        => '0123456789',
    };
    $otp = '';
    for ($i = 0; $i < $otp_length; $i++) {
        $otp .= $characters[random_int(0, strlen($characters) - 1)];
    }
    return $otp_case_sensitive ? $otp : strtolower($otp);
}

// CAPTCHA verification functions
function verify_recaptcha_v2($response, $secret_key) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $response = json_decode($result);
    return $response->success ?? false;
}

function verify_recaptcha_v3($response, $secret_key) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $response = json_decode($result);
    return ($response->success ?? false) && ($response->score >= 0.5);
}

function verify_hcaptcha($response, $secret_key) {
    $url = 'https://hcaptcha.com/siteverify';
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $response = json_decode($result);
    return $response->success ?? false;
}

// Send verification email
function send_verification_email($email, $otp) {
    global $verification_email_subject, $verification_email_message, $email_verification_type,
           $smtp_host, $smtp_port, $smtp_username, $smtp_password, $smtp_from,
           $sendmail_path;

    require_once 'PHPMailer/PHPMailer.php';
    require_once 'PHPMailer/SMTP.php';
    require_once 'PHPMailer/Exception.php';

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    try {
        switch ($email_verification_type) {
            case 'smtp':
                $mail->isSMTP();
                $mail->Host       = $smtp_host;
                $mail->Port       = $smtp_port;
                $mail->SMTPAuth   = true;
                $mail->Username   = $smtp_username;
                $mail->Password   = $smtp_password;
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                break;
            case 'sendmail':
                $mail->isSendmail();
                $mail->Sendmail = $sendmail_path;
                break;
            default:
                return false;
        }
        $mail->setFrom($smtp_from);
        $mail->addAddress($email);
        $mail->Subject = $verification_email_subject;
        $mail->Body    = $verification_email_message . $otp;
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

// Handle only register request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register') {
    // Validate CSRF token
    $csrf_token = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_STRING);
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        exit("Invalid CSRF token.");
    }

    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $password = $_POST['password'] ?? '';
    $email    = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);

    // Check email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        exit("Invalid email format.");
    }
    // Check password strength
    if (!isPasswordStrongEnough($password)) {
        exit("Password does not meet strength requirements.");
    }

    // Handle verification
    $verification_passed = true;
    $verification_token  = '';
    if ($verification_method !== 'none') {
        switch ($verification_method) {
            case 'email':
                $verification_token = generate_otp();
                if (!send_verification_email($email, $verification_token)) {
                    error_log("Failed to send verification email to: " . $email);
                    exit("Failed to send verification email.");
                }
                break;
                
            case 'recaptcha_v2':
                $captcha_response = $_POST['g-recaptcha-response'] ?? '';
                $verification_passed = verify_recaptcha_v2($captcha_response, $recaptcha_v2_secret_key);
                break;
                
            case 'recaptcha_v3':
                $captcha_response = $_POST['g-recaptcha-response'] ?? '';
                $verification_passed = verify_recaptcha_v3($captcha_response, $recaptcha_v3_secret_key);
                break;
                
            case 'hcaptcha':
                $captcha_response = $_POST['h-captcha-response'] ?? '';
                $verification_passed = verify_hcaptcha($captcha_response, $hcaptcha_secret_key);
                break;
        }
        
        if (!$verification_passed) {
            exit("Verification failed. Please try again.");
        }
    }

    // Check if user exists
    $stmt = $mysqli->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($res->num_rows > 0) {
        exit("Username or email already exists.");
    }

    // Insert new user
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $otp_expiry      = time() + ($otp_expiry_minutes * 60);
    $is_verified     = ($verification_method === 'email') ? 0 : 1;

    $stmt = $mysqli->prepare("
        INSERT INTO users (
            username,
            email,
            password,
            verification_token,
            is_verified,
            otp_expiry
        ) VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmt->bind_param("ssssii", $username, $email, $hashed_password, $verification_token, $is_verified, $otp_expiry);
    if ($stmt->execute()) {
        if ($verification_method === 'email') {
            $_SESSION['pending_verification'] = true;
            $_SESSION['pending_email'] = $email;
            header("Location: verify.php");
            exit();
        } else {
            $_SESSION['user_id']  = $mysqli->insert_id;
            $_SESSION['username'] = $username;
            echo "Registration successful.";
        }
    } else {
        error_log("Registration failed: " . $mysqli->error);
        header("HTTP/1.1 500 Internal Server Error");
        exit("Registration failed");
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
  <title>Register</title>
  <link rel="stylesheet" href="css/style.css" />
</head>
<body>
  <div class="container">
    <h1>Register</h1>

    <form action="" method="POST">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>" />
      <input type="hidden" name="action" value="register" />

      <div class="form-field">
        <label for="reg-user">Username</label>
        <input type="text" id="reg-user" name="username" required />
      </div>

      <div class="form-field">
        <label for="reg-email">Email</label>
        <input type="email" id="reg-email" name="email" required />
      </div>

      <div class="form-field">
        <label for="reg-pass">Password</label>
        <input type="password" id="reg-pass" name="password" required />
      </div>

      <?php if ($verification_method === 'recaptcha_v2'): ?>
        <div class="g-recaptcha" data-sitekey="<?php echo htmlspecialchars($recaptcha_v2_site_key); ?>"></div>
        <script src="https://www.google.com/recaptcha/api.js"></script>
      <?php elseif ($verification_method === 'recaptcha_v3'): ?>
        <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">
        <script src="https://www.google.com/recaptcha/api.js?render=<?php echo htmlspecialchars($recaptcha_v3_site_key); ?>"></script>
        <script>
          grecaptcha.ready(function() {
            grecaptcha.execute('<?php echo htmlspecialchars($recaptcha_v3_site_key); ?>', {action: 'register'}).then(function(token) {
              document.getElementById('g-recaptcha-response').value = token;
            });
          });
        </script>
      <?php elseif ($verification_method === 'hcaptcha'): ?>
        <div class="h-captcha" data-sitekey="<?php echo htmlspecialchars($hcaptcha_site_key); ?>"></div>
        <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
      <?php endif; ?>

      <input type="submit" value="Register" />
    </form>

    <div class="switch-link">
      <p>Already have an account? <a href="login.php">Login</a></p>
    </div>
  </div>

  <script src="js/animation.js"></script>
</body>
</html>