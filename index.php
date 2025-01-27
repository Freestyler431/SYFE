<?php
session_start();
require 'config.php';

function isValidSession() {
    return isset($_SESSION['user_id']) && 
           isset($_SESSION['username']) && 
           isset($_SESSION['last_login']);
}

// Check if login is required and handle session
if ($require_login === true) {
    if (!isValidSession()) {
        header("Location: login.php");
        exit();
    }
} else {
    
}

// Main content of index.php below
?>

<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <?php if (isValidSession()): ?>
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
        <a href="logout.php">Logout</a>
    <?php else: ?>
        <h1>Welcome Guest</h1>
        <?php if ($require_login): ?>
            <a href="login.php">Login</a>
        <?php endif; ?>
    <?php endif; ?>
    
</body>
</html>