<?php
require_once 'config.php';
require_once 'utils/security.php';
require_once 'utils.php';

start_secure_session();

// Check if verification is pending
if (!isset($_SESSION['pending_verification']) || !isset($_SESSION['pending_email'])) {
    header("Location: login.php");
    exit();
}

$conn = get_db_connection();
$security = new Security($conn);

$email = $_SESSION['pending_email'];
$error_message = '';
$success_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $otp = $_POST['otp'] ?? '';

    if ($action === 'verify') {
        $stmt = $conn->prepare("SELECT id, verification_token, otp_expiry FROM users WHERE email = ? AND is_verified = 0");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user) {
            if (time() > $user['otp_expiry']) {
                $error_message = "Code expired.";
            } elseif ($otp === $user['verification_token']) {
                $stmt = $conn->prepare("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?");
                $stmt->execute([$user['id']]);
                
                unset($_SESSION['pending_verification']);
                unset($_SESSION['pending_email']);
                $_SESSION['user_id'] = $user['id'];
                
                header("Location: index.php");
                exit;
            } else {
                $error_message = "Invalid code.";
            }
        } else {
            $error_message = "Invalid request.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Verify Email</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
<div class="container">
    <h1>Verify Email</h1>
    <?php if ($error_message): ?>
        <p style="color:red"><?= htmlspecialchars($error_message) ?></p>
    <?php endif; ?>
    
    <p>Code sent to <?= htmlspecialchars($email) ?></p>
    
    <form method="POST">
        <input type="hidden" name="action" value="verify">
        <input type="text" name="otp" placeholder="Enter Code" required>
        <button type="submit">Verify</button>
    </form>
</div>
</body>
</html>