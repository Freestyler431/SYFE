<?php
require_once 'config.php';
require_once 'utils/security.php';

start_secure_session();

// Security Headers
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: no-referrer");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

$conn = get_db_connection();
$upload_dir = __DIR__ . '/storage/chunks/';

// Publicly retrieve file metadata and chunks (Only for files marked public)
if (isset($_GET['action']) && $_GET['action'] === 'public_get' && isset($_GET['file_id_public'])) {
    $file_id_public = $_GET['file_id_public'];
    
    // Check if the file is public
    $stmt = $conn->prepare("SELECT id, metadata_blob, total_chunks FROM files WHERE file_id_public = ? AND is_public = 1");
    $stmt->execute([$file_id_public]);
    $file = $stmt->fetch();

    if (!$file) {
        header("HTTP/1.1 404 Not Found");
        die(json_encode(['error' => 'File not found or private']));
    }

    // Fetch chunk locations
    $stmt = $conn->prepare("SELECT chunk_index, chunk_hash, chunk_iv, storage_path FROM file_chunks WHERE file_id = ? ORDER BY chunk_index ASC");
    $stmt->execute([$file['id']]);
    $chunks = $stmt->fetchAll();

    // Read chunk data from storage
    foreach ($chunks as &$chunk) {
        $chunk['data'] = file_get_contents($upload_dir . $chunk['storage_path']);
    }

    echo json_encode([
        'metadata' => $file['metadata_blob'],
        'chunks' => $chunks
    ]);
    exit;
}

if (!isset($_SESSION['user_id'])) {
    die(json_encode(['error' => 'Not authenticated']));
}

$conn = get_db_connection();
$upload_dir = __DIR__ . '/storage/chunks/';

// Get list of user's files
if (isset($_GET['action']) && $_GET['action'] === 'list') {
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT file_id_public, metadata_blob, total_chunks, is_public, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$user_id]);
    $files = $stmt->fetchAll();
    echo json_encode($files);
    exit;
}

// Get file metadata and chunks
if (isset($_GET['file_id_public'])) {
    $file_id_public = $_GET['file_id_public'];
    $user_id = $_SESSION['user_id'];

    $stmt = $conn->prepare("SELECT id, metadata_blob, total_chunks FROM files WHERE file_id_public = ? AND user_id = ?");
    $stmt->execute([$file_id_public, $user_id]);
    $file = $stmt->fetch();

    if (!$file) die(json_encode(['error' => 'File not found']));

    // Fetch chunk locations
    $stmt = $conn->prepare("SELECT chunk_index, chunk_hash, chunk_iv, storage_path FROM file_chunks WHERE file_id = ? ORDER BY chunk_index ASC");
    $stmt->execute([$file['id']]);
    $chunks = $stmt->fetchAll();

    // Read chunk data from storage
    foreach ($chunks as &$chunk) {
        $chunk['data'] = file_get_contents($upload_dir . $chunk['storage_path']);
    }

    echo json_encode([
        'metadata' => $file['metadata_blob'],
        'chunks' => $chunks
    ]);
    exit;
}
?>