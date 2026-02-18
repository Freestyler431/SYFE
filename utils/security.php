<?php
// Enhanced Security Utilities
require_once __DIR__ . '/../config.php';

class Security {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function checkRateLimit($ip, $type = 'login') {
        $limit = 5; // 5 attempts
        $window = 300; // 5 minutes

        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM login_logs WHERE ip_address = ? AND attempt_time > ?");
        $stmt->execute([$ip, time() - $window]);
        $count = $stmt->fetchColumn();

        if ($count >= $limit) {
            return false;
        }
        return true;
    }

    public function logAttempt($ip, $username, $success) {
        $stmt = $this->pdo->prepare("INSERT INTO login_logs (ip_address, username, attempt_time, success) VALUES (?, ?, ?, ?)");
        $stmt->execute([$ip, $username, time(), $success ? 1 : 0]);
    }

    public function generateFakeSalt($username) {
        global $server_pepper;
        // Deterministic but unpredictable without secret
        return hash_hmac('sha256', $username, $server_pepper);
    }
}

function get_db_connection() {
    global $mysql_host, $mysql_database, $mysql_user, $mysql_password;
    try {
        $dsn = "mysql:host=$mysql_host;dbname=$mysql_database;charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        return new PDO($dsn, $mysql_user, $mysql_password, $options);
    } catch (PDOException $e) {
        error_log("DB Connection Failed: " . $e->getMessage());
        die("System error. Please try again later.");
    }
}
?>