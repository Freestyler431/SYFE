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

/**
 * Check if the user has access to the file and return file info
 */
function get_file_with_access($conn, $file_id_public, $is_public_request = false) {
    if ($is_public_request) {
        $stmt = $conn->prepare("SELECT id, user_id, metadata_blob, total_chunks, is_public FROM files WHERE file_id_public = ? AND is_public = 1");
        $stmt->execute([$file_id_public]);
    } else {
        if (!isset($_SESSION['user_id'])) return null;
        $user_id = $_SESSION['user_id'];
        $stmt = $conn->prepare("SELECT id, user_id, metadata_blob, total_chunks, is_public FROM files WHERE file_id_public = ? AND user_id = ?");
        $stmt->execute([$file_id_public, $user_id]);
    }
    return $stmt->fetch();
}

// Action: List User's Files
if (isset($_GET['action']) && $_GET['action'] === 'list') {
    if (!isset($_SESSION['user_id'])) {
        die(json_encode(['error' => 'Not authenticated']));
    }
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT file_id_public, metadata_blob, total_chunks, is_public, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$user_id]);
    $files = $stmt->fetchAll();
    echo json_encode($files);
    exit;
}

// Action: Get File Info (Metadata and Chunk List)
if (isset($_GET['file_id_public']) && (!isset($_GET['action']) || ($_GET['action'] === 'public_get'))) {
    $file_id_public = $_GET['file_id_public'];
    $is_public_request = (isset($_GET['action']) && $_GET['action'] === 'public_get');
    
    $file = get_file_with_access($conn, $file_id_public, $is_public_request);

    if (!$file) {
        header("HTTP/1.1 404 Not Found");
        die(json_encode(['error' => 'File not found or access denied']));
    }

    // Fetch chunk metadata (indices, hashes, IVs) but NOT the actual data
    $stmt = $conn->prepare("SELECT chunk_index, chunk_hash, chunk_iv FROM file_chunks WHERE file_id = ? ORDER BY chunk_index ASC");
    $stmt->execute([$file['id']]);
    $chunks = $stmt->fetchAll();

    echo json_encode([
        'metadata' => $file['metadata_blob'],
        'total_chunks' => $file['total_chunks'],
        'chunks' => $chunks
    ]);
    exit;
}

// Action: Get Individual Chunk Data
if (isset($_GET['action']) && $_GET['action'] === 'get_chunk' && isset($_GET['file_id_public']) && isset($_GET['chunk_index'])) {
    $file_id_public = $_GET['file_id_public'];
    $chunk_index = (int)$_GET['chunk_index'];
    
    // Check if the user has access (either public or owner)
    // First try public
    $file = get_file_with_access($conn, $file_id_public, true);
    if (!$file) {
        // Then try as owner
        $file = get_file_with_access($conn, $file_id_public, false);
    }

    if (!$file) {
        header("HTTP/1.1 404 Not Found");
        die(json_encode(['error' => 'File not found or access denied']));
    }

    // Fetch the chunk storage path
    $stmt = $conn->prepare("SELECT storage_path FROM file_chunks WHERE file_id = ? AND chunk_index = ?");
    $stmt->execute([$file['id'], $chunk_index]);
    $chunk = $stmt->fetch();

    if (!$chunk) {
        header("HTTP/1.1 404 Not Found");
        die(json_encode(['error' => 'Chunk not found']));
    }

    $file_path = $upload_dir . $chunk['storage_path'];
    if (file_exists($file_path)) {
        // Output raw chunk data (hex-encoded string)
        header('Content-Type: text/plain');
        echo file_get_contents($file_path);
    } else {
        header("HTTP/1.1 404 Not Found");
        die(json_encode(['error' => 'Storage file missing']));
    }
    exit;
}

header("HTTP/1.1 400 Bad Request");
die(json_encode(['error' => 'Invalid request']));
?>
