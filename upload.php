<?php
require_once 'config.php';
require_once 'utils/security.php';

start_secure_session();

// Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: no-referrer");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

if (!isset($_SESSION['user_id'])) {
    die(json_encode(['error' => 'Not authenticated']));
}

// CSRF Check
$headers = getallheaders();
$csrf_token = $_POST['csrf_token'] ?? $headers['X-CSRF-Token'] ?? '';
if (!hash_equals($_SESSION['csrf_token'] ?? '', $csrf_token)) {
    header("HTTP/1.1 403 Forbidden");
    die(json_encode(['error' => 'Invalid CSRF Token']));
}

$conn = get_db_connection();
$upload_dir = __DIR__ . '/storage/chunks/';
if (!is_dir($upload_dir)) mkdir($upload_dir, 0755, true);

// Handle Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $user_id = $_SESSION['user_id'];

    if ($action === 'create_file') {
        // Step 1: Initialize File Entry with Metadata Blob
        $metadata_blob = $_POST['metadata'] ?? '';
        $total_chunks = (int)($_POST['total_chunks'] ?? 0);
        $is_public = (int)($_POST['is_public'] ?? 0);
        $file_id_public = bin2hex(random_bytes(16));

        if (empty($metadata_blob) || $total_chunks <= 0) {
            die(json_encode(['error' => 'Invalid metadata']));
        }

        $stmt = $conn->prepare("INSERT INTO files (user_id, metadata_blob, total_chunks, file_id_public, is_public) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $metadata_blob, $total_chunks, $file_id_public, $is_public]);
        
        echo json_encode(['file_id' => $conn->lastInsertId(), 'file_id_public' => $file_id_public]);
        exit;
    }

    if ($action === 'upload_chunk') {
        // Step 2: Upload Individual Encrypted Chunks
        $file_id = (int)($_POST['file_id'] ?? 0);
        $chunk_index = (int)($_POST['chunk_index'] ?? 0);
        $chunk_hash = $_POST['chunk_hash'] ?? '';
        $chunk_iv = $_POST['chunk_iv'] ?? '';
        $chunk_data = $_POST['chunk_data'] ?? ''; // Encrypted hex

        if (empty($chunk_data)) {
            die(json_encode(['error' => 'Chunk data empty (Check PHP post_max_size)']));
        }
        
        // Security check: ensure user owns the file
        $stmt = $conn->prepare("SELECT id FROM files WHERE id = ? AND user_id = ?");
        $stmt->execute([$file_id, $user_id]);
        if (!$stmt->fetch()) die(json_encode(['error' => 'Unauthorized']));

        // Random storage path to hide relationships
        $storage_name = bin2hex(random_bytes(32));
        $storage_path = $upload_dir . $storage_name;

        if (file_put_contents($storage_path, $chunk_data)) {
            $stmt = $conn->prepare("INSERT INTO file_chunks (file_id, chunk_index, chunk_hash, chunk_iv, storage_path) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$file_id, $chunk_index, $chunk_hash, $chunk_iv, $storage_name]);
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['error' => 'Storage failed']);
        }
        exit;
    }

    if ($action === 'delete_file') {
        $file_id_public = $_POST['file_id_public'] ?? '';
        $user_id = $_SESSION['user_id'];

        // Find the file and ensure the user owns it
        $stmt = $conn->prepare("SELECT id FROM files WHERE file_id_public = ? AND user_id = ?");
        $stmt->execute([$file_id_public, $user_id]);
        $file = $stmt->fetch();

        if (!$file) {
            die(json_encode(['error' => 'File not found or unauthorized']));
        }

        $file_id = $file['id'];

        // Get all chunk storage paths to delete files
        $stmt = $conn->prepare("SELECT storage_path FROM file_chunks WHERE file_id = ?");
        $stmt->execute([$file_id]);
        $chunks = $stmt->fetchAll();

        foreach ($chunks as $chunk) {
            $chunk_path = $upload_dir . $chunk['storage_path'];
            if (file_exists($chunk_path)) {
                unlink($chunk_path);
            }
        }

        // Delete from database
        $stmt = $conn->prepare("DELETE FROM files WHERE id = ?");
        $stmt->execute([$file_id]);

        echo json_encode(['status' => 'success', 'message' => 'File deleted successfully']);
        exit;
    }
}
?>
