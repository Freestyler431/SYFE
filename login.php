<?php
session_start();
require 'config.php';

// Database connection
$mysqli = new mysqli($mysql_host, $mysql_user, $mysql_password, $mysql_database);
if ($mysqli->connect_error) {
    error_log("MySQL connection failed: " . $mysqli->connect_error);
    header("HTTP/1.1 500 Internal Server Error");
    exit();
}

// Verification handler functions
function verify_recaptcha_v2($response) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = array(
        'secret' => $GLOBALS['recaptcha_v2_secret_key'],
        'response' => $response
    );
    $options = array(
        'http' => array(
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        )
    );
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $resultJson = json_decode($result);
    return isset($resultJson->success) ? $resultJson->success : false;
}

function verify_recaptcha_v3($response) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = array(
        'secret' => $GLOBALS['recaptcha_v3_secret_key'],
        'response' => $response
    );
    $options = array(
        'http' => array(
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        )
    );
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $resultJson = json_decode($result);
    return (isset($resultJson->success) && $resultJson->success && $resultJson->score >= 0.5);
}

function verify_hcaptcha($response) {
    $url = 'https://hcaptcha.com/siteverify';
    $data = array(
        'secret' => $GLOBALS['hcaptcha_secret_key'],
        'response' => $response
    );
    $options = array(
        'http' => array(
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        )
    );
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $resultJson = json_decode($result);
    return isset($resultJson->success) ? $resultJson->success : false;
}

function send_verification_email($email, $token) {
    $to = $email;
    $subject = "Email Verification";
    $message = "Click the link to verify your email: http://yourdomain.com/verify.php?token=" . $token;
    $headers = "From: noreply@yourdomain.com";
    
    return mail($to, $subject, $message, $headers);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING);

    // Verification check based on method
    $verification_passed = false;
    switch($verification_method) {
        case 'none':
            $verification_passed = true;
            break;
            
        case 'email':
            if ($action == 'register') {
                $verification_token = bin2hex(random_bytes(32));
                if (send_verification_email($email, $verification_token)) {
                    $verification_passed = true;
                }
            } else {
                $verification_passed = true; // For login
            }
            break;
            
        case 'recaptcha_v2':
            $captcha_response = filter_input(INPUT_POST, 'g-recaptcha-response', FILTER_SANITIZE_STRING);
            $verification_passed = verify_recaptcha_v2($captcha_response);
            break;
            
        case 'recaptcha_v3':
            $captcha_response = filter_input(INPUT_POST, 'g-recaptcha-response', FILTER_SANITIZE_STRING);
            $verification_passed = verify_recaptcha_v3($captcha_response);
            break;
            
        case 'hcaptcha':
            $captcha_response = filter_input(INPUT_POST, 'h-captcha-response', FILTER_SANITIZE_STRING);
            $verification_passed = verify_hcaptcha($captcha_response);
            break;
    }

    if (!$verification_passed) {
        error_log("Verification failed for method: " . $verification_method);
        exit("Verification failed. Please try again.");
    }

    if ($action == 'register') {
        $stmt = $mysqli->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            exit("Username or email already exists");
        }
        
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $is_verified = ($verification_method != 'email');
        $stmt = $mysqli->prepare("INSERT INTO users (username, email, password, verification_token, is_verified) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssi", $username, $email, $hashed_password, $verification_token, $is_verified);
        
        if ($stmt->execute()) {
            if ($verification_method == 'email') {
                echo "Please check your email to verify your account";
            } else {
                $_SESSION['user_id'] = $mysqli->insert_id;
                $_SESSION['username'] = $username;
                echo "Registration successful";
            }
        } else {
            error_log("Registration failed: " . $mysqli->error);
            header("HTTP/1.1 500 Internal Server Error");
            exit("Registration failed");
        }
    } 
    elseif ($action == 'login') {
        $stmt = $mysqli->prepare("SELECT id, password, is_verified FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            if ($verification_method == 'email' && !$user['is_verified']) {
                exit("Please verify your email first");
            }
            if (password_verify($password, $user['password'])) {
                // Regenerate session for security
                session_regenerate_id(true);
                
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $username;
                $_SESSION['last_login'] = time();
                
                // Log successful login
                error_log("Successful login: " . $username);
                
                // Set security headers
                header("Cache-Control: no-store, no-cache, must-revalidate");
                header("Pragma: no-cache");
                
                // Redirect to index page
                header("Location: index.php");
                exit();
            } else {
                error_log("Failed login attempt for user: " . $username);
                exit("Invalid credentials");
            }
        } else {
            error_log("Failed login attempt for non-existent user: " . $username);
            exit("Invalid credentials");
        }
    }
    
    $stmt->close();
}

$mysqli->close();
?>