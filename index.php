<?php
require_once 'config.php';
start_secure_session();

// Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: no-referrer");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

function isValidSession() {
    return isset($_SESSION['user_id']) && 
           isset($_SESSION['username']);
}

// Check if login is required and handle session
if ($require_login === true) {
    if (!isValidSession()) {
        header("Location: login.php");
        exit();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SYFE - Secure Dashboard</title>
  <link rel="stylesheet" href="css/style.css" />
  <script src="js/zk-auth.js"></script>
</head>
<body>
  <div class="container">
    <h1>Welcome, <?= htmlspecialchars($_SESSION['username']); ?></h1>
    <a href="logout.php">Logout</a>

    <div class="upload-section">
      <h3>Upload File (Zero-Knowledge)</h3>
      <input type="file" id="fileInput" />
      <label><input type="checkbox" id="isPublic" /> Shareable?</label>
      <button onclick="handleUpload()">Securely Upload</button>
      <div id="uploadStatus"></div>
    </div>

    <div class="files-section">
      <h3>My Encrypted Files</h3>
      <table id="fileTable">
        <thead>
          <tr>
            <th>Name</th>
            <th>Size</th>
            <th>Uploaded At</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="fileList"></tbody>
      </table>
    </div>
  </div>

  <script>
    // Retrieve encryption key from session storage
    const user = "<?= $_SESSION['username'] ?>";
    const encryptionKey = sessionStorage.getItem('enc_key_' + user);

    if (!encryptionKey) {
        alert("Session encryption key missing. Please log in again.");
        window.location.href = 'logout.php';
    }

    async function handleUpload() {
        const file = document.getElementById('fileInput').files[0];
        if (!file) return;

        const status = document.getElementById('uploadStatus');
        status.innerText = "Encrypting and splitting...";

        // 1. Encrypt Metadata
        const metadata = { name: file.name, size: file.size, type: file.type };
        const encMetadata = await ZKAuth.encryptMetadata(metadata, encryptionKey);
        
        // 2. Encrypt & Split File
        const chunks = await ZKAuth.encryptFile(file, encryptionKey);

        // 3. Register File with Server
        const fd = new FormData();
        fd.append('action', 'create_file');
        fd.append('csrf_token', "<?= $_SESSION['csrf_token'] ?>");
        fd.append('metadata', JSON.stringify(encMetadata)); // Store as {blob: hex, iv: hex}
        fd.append('total_chunks', chunks.length);
        fd.append('is_public', document.getElementById('isPublic').checked ? 1 : 0);

        const res = await fetch('upload.php', { method: 'POST', body: fd });
        const data = await res.json();

        if (data.file_id) {
            // 4. Upload Chunks
            for (let chunk of chunks) {
                status.innerText = `Uploading chunk ${chunk.index + 1}/${chunks.length}...`;
                const cfd = new FormData();
                cfd.append('action', 'upload_chunk');
                cfd.append('csrf_token', "<?= $_SESSION['csrf_token'] ?>");
                cfd.append('file_id', data.file_id);
                cfd.append('chunk_index', chunk.index);
                cfd.append('chunk_hash', chunk.hash);
                cfd.append('chunk_data', chunk.data);
                cfd.append('chunk_iv', chunk.iv); // Store IV for decryption
                
                // Store IV in metadata if not already there, but standard AES-GCM needs it per chunk
                // We'll update the metadata with all chunk IVs or store them per chunk in DB
                await fetch('upload.php', { method: 'POST', body: cfd });
            }
            status.innerText = "Upload complete!";
            loadFiles();
        }
    }

    async function loadFiles() {
        const res = await fetch('download.php?action=list');
        const files = await res.json();
        const list = document.getElementById('fileList');
        list.innerHTML = "";

        for (let f of files) {
            // Decrypt Metadata
            const encMeta = JSON.parse(f.metadata_blob);
            let meta;
            try {
                meta = await ZKAuth.decryptMetadata(encMeta.blob, encMeta.iv, encryptionKey);
            } catch(e) {
                meta = { name: "Decryption Failed", size: 0 };
            }

            const shareLink = f.is_public == 1 ? `<button onclick="copyShareLink('${f.file_id_public}')">Copy Link</button>` : '';

            const row = `<tr>
                <td>${meta.name}</td>
                <td>${(meta.size / 1024 / 1024).toFixed(2)} MB</td>
                <td>${f.created_at}</td>
                <td>
                    <button onclick="handleDownload('${f.file_id_public}')">Download</button>
                    ${shareLink}
                </td>
            </tr>`;
            list.innerHTML += row;
        }
    }

    function copyShareLink(publicId) {
        // Link with KEY in Hash (Secure for direct sharing)
        const baseUrl = window.location.href.split('index.php')[0];
        const fullLink = `${baseUrl}share.php?id=${publicId}#${encryptionKey}`;
        
        navigator.clipboard.writeText(fullLink).then(() => {
            alert("Share Link copied to clipboard! (Includes decryption key in #)");
        });
    }

    async function handleDownload(publicId) {
        const res = await fetch(`download.php?file_id_public=${publicId}`);
        const data = await res.json();
        
        // 1. Decrypt Metadata
        const encMeta = JSON.parse(data.metadata);
        const meta = await ZKAuth.decryptMetadata(encMeta.blob, encMeta.iv, encryptionKey);
        
        console.log("Downloading:", meta.name);

        // 2. Decrypt Chunks
        let decryptedChunks = [];
        for (let c of data.chunks) {
            const dec = await ZKAuth.decryptChunk(c.data, c.chunk_iv, encryptionKey);
            decryptedChunks.push(dec);
        }

        // 3. Reassemble and Download
        const finalBlob = new Blob(decryptedChunks, { type: meta.type });
        const url = URL.createObjectURL(finalBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = meta.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    loadFiles();
  </script>
</body>
</html>