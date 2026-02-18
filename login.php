<?php
require_once 'config.php';
require_once 'utils/security.php';

start_secure_session();

$conn = get_db_connection();
$security = new Security($conn);

// API Endpoint for Salt Retrieval (User Enumeration Protected)
if (isset($_GET['action']) && $_GET['action'] === 'get_salt') {
    header('Content-Type: application/json');
    $username = $_GET['username'] ?? '';
    
    $stmt = $conn->prepare("SELECT salt FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user) {
        echo json_encode(['salt' => $user['salt']]);
    } else {
        // Return deterministic fake salt to prevent timing attacks/enumeration
        echo json_encode(['salt' => $security->generateFakeSalt($username)]); 
    }
    exit;
}

// Handle Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    $ip = $_SERVER['REMOTE_ADDR'];
    
    // Rate Limiting
    if (!$security->checkRateLimit($ip)) {
        die("Too many login attempts. Please try again later.");
    }

    $username = $_POST['username'] ?? '';
    $auth_key = $_POST['auth_key'] ?? ''; // Client sends Hash(AuthKey)

    // Verify User
    $stmt = $conn->prepare("SELECT id, auth_verifier, is_verified, login_attempts, lockout_until FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user) {
        // Check Lockout
        if ($user['lockout_until'] > time()) {
            $security->logAttempt($ip, $username, false);
            die("Account locked. Try again in 15 minutes.");
        }

        // Verify Hash
        if (password_verify($auth_key, $user['auth_verifier'])) {
            // Success
            // Reset lockout counters
            $conn->prepare("UPDATE users SET login_attempts = 0, lockout_until = 0 WHERE id = ?")->execute([$user['id']]);
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $username;
            
            $security->logAttempt($ip, $username, true);
            
            if (!$user['is_verified'] && !$test_mode) {
                $_SESSION['pending_verification'] = true;
                $_SESSION['pending_email'] = $username; // Email not fetched here, but verify logic handles it
                header("Location: verify.php");
                exit;
            }

            if ($test_mode && !$user['is_verified']) {
                $conn->prepare("UPDATE users SET is_verified = 1 WHERE id = ?")->execute([$user['id']]);
            }

            header("Location: index.php");
            exit;
        } else {
            // Failed Password
            $attempts = $user['login_attempts'] + 1;
            $lockout = ($attempts >= 5) ? time() + 900 : 0; // Lockout for 15 mins after 5 failed attempts
            
            $conn->prepare("UPDATE users SET login_attempts = ?, lockout_until = ? WHERE id = ?")->execute([$attempts, $lockout, $user['id']]);
            
            $security->logAttempt($ip, $username, false);
            die("Invalid credentials");
        }
    } else {
        // User not found (Timing Attack Protection: Simulate verification time)
        // password_verify('dummy', '$2y$10$dummyhash...'); 
        $security->logAttempt($ip, $username, false);
        die("Invalid credentials");
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Login</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="js/zk-auth.js"></script>
</head>
<body>
<div class="container auth-container">
    <div class="auth-header">
        <h1>Welcome Back</h1>
        <p style="color: var(--text-secondary);">Securely access your encrypted vault</p>
    </div>

    <form id="loginForm" method="POST">
        <input type="hidden" name="action" value="login">
        <input type="hidden" name="auth_key" id="auth_key">

        <div class="form-field">
            <label>Username</label>
            <input type="text" name="username" id="username" placeholder="Enter your username" required>
        </div>

        <div class="form-field">
            <label>Password</label>
            <input type="password" id="password" placeholder="••••••••••••" required>
        </div>

        <button type="submit" class="btn-primary">Sign In</button>
    </form>
    
    <div class="switch-link">
        Don't have an account? <a href="register.php">Create one securely</a>
    </div>
</div>

<script>
document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;

    // 1. Get Salt
    const res = await fetch(`login.php?action=get_salt&username=${encodeURIComponent(user)}`);
    const data = await res.json();
    
    if (!data.salt) {
        alert("Error retrieving login parameters");
        return;
    }

    // 2. Derive Key
    const derivedBits = await ZKAuth.deriveKey(pass, data.salt);
    const keys = await ZKAuth.splitKey(derivedBits);

    // 3. Set Auth Key for Server
    document.getElementById('auth_key').value = keys.authKeyHex;
    
    // 4. Store Encryption Key locally for the session
    // This key is never sent to the server.
    sessionStorage.setItem('enc_key_' + user, keys.encryptionKeyHex);

    // 5. Submit
    this.submit();
});
</script>
</body>
</html>