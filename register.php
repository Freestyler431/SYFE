<?php
require_once 'config.php';
require_once 'utils/security.php';
require_once 'utils.php';

start_secure_session();

// CSRF Protection
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$conn = get_db_connection();
$security = new Security($conn);

// Handle Registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register') {
    $csrf_token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        die("Invalid CSRF token");
    }

    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $salt = $_POST['salt'] ?? '';
    $auth_key = $_POST['auth_key'] ?? ''; // This is the Hashed Auth Key from client

    if (empty($username) || empty($email) || empty($salt) || empty($auth_key)) {
        die("Missing required fields");
    }

    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format");
    }

    // Check if user exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $stmt->execute([$username, $email]);
    if ($stmt->fetch()) {
        die("Username or Email already taken");
    }

    // Server-Side Hashing (bcrypt/argon2) of the Client's Auth Key
    // The server treats the Auth Key as the "password"
    $server_hash = password_hash($auth_key, PASSWORD_DEFAULT);
    
    // Verification Token
    $verification_token = bin2hex(random_bytes(16));
    $otp_expiry = time() + 600; // 10 minutes

    try {
        $stmt = $conn->prepare("INSERT INTO users (username, email, auth_verifier, salt, verification_token, otp_expiry, is_verified) VALUES (?, ?, ?, ?, ?, ?, 0)");
        $stmt->execute([$username, $email, $server_hash, $salt, $verification_token, $otp_expiry]);
        
        // Send Email
        if (send_verification_email($email, $verification_token)) {
            $_SESSION['pending_verification'] = true;
            $_SESSION['pending_email'] = $email;
            header("Location: verify.php");
            exit;
        } else {
            die("Failed to send verification email");
        }
    } catch (PDOException $e) {
        error_log($e->getMessage());
        die("Registration failed");
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Registration - Zero Knowledge</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="js/zk-auth.js"></script>
</head>
<body>
<div class="container">
    <h1>Register (Zero-Knowledge)</h1>
    <form id="regForm" method="POST">
        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
        <input type="hidden" name="action" value="register">
        
        <!-- Hidden fields for ZK Auth -->
        <input type="hidden" name="salt" id="salt">
        <input type="hidden" name="auth_key" id="auth_key">

        <div class="form-field">
            <label>Username</label>
            <input type="text" name="username" id="username" required>
        </div>
        
        <div class="form-field">
            <label>Email</label>
            <input type="email" name="email" required>
        </div>

        <div class="form-field">
            <label>Password</label>
            <!-- Password is NEVER sent to server -->
            <input type="password" id="password" required>
        </div>

        <button type="submit">Register Securely</button>
    </form>
    <p>Already have an account? <a href="login.php">Login</a></p>
</div>

<script>
document.getElementById('regForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const pass = document.getElementById('password').value;
    const user = document.getElementById('username').value;
    
    if (pass.length < 12) {
        alert("Password must be at least 12 characters");
        return;
    }

    // 1. Generate Salt
    const saltHex = ZKAuth.generateSalt();
    document.getElementById('salt').value = saltHex;

    // 2. Derive Key
    const keyMaterial = await ZKAuth.deriveKey(pass, saltHex);
    
    // 3. Split Key
    const keys = await ZKAuth.splitKey(keyMaterial);
    
    // 4. Set Auth Key for Server
    document.getElementById('auth_key').value = keys.authKeyHex; // This is the hashed auth key

    // 5. Store Encryption Key (Local Storage / Session Storage for now)
    // In a real app, this would be used to decrypt the user's file vault
    sessionStorage.setItem('enc_key_' + user, keys.encryptionKeyHex);

    // 6. Submit
    this.submit();
});
</script>
</body>
</html>