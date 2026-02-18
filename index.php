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
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];
        if (!file) {
            console.warn("No file selected");
            return;
        }

        const status = document.getElementById('uploadStatus');
        status.innerText = "Initializing upload...";
        console.log("Starting upload for:", file.name);

        try {
            const csrfToken = "<?= $_SESSION['csrf_token'] ?>";
            
            // 1. Encrypt Metadata
            const metadata = { name: file.name, size: file.size, type: file.type };
            const encMetadata = await ZKAuth.encryptMetadata(metadata, encryptionKey);
            
            const chunkSize = 1 * 1024 * 1024; // 1MB
            const totalChunks = Math.ceil(file.size / chunkSize);

            // 2. Register File with Server
            const fd = new FormData();
            fd.append('action', 'create_file');
            fd.append('csrf_token', csrfToken);
            fd.append('metadata', JSON.stringify(encMetadata));
            fd.append('total_chunks', totalChunks);
            fd.append('is_public', document.getElementById('isPublic').checked ? 1 : 0);

            console.log("Registering file...");
            const res = await fetch('upload.php', { method: 'POST', body: fd });
            const data = await res.json();
            console.log("Registration response:", data);

            if (!data.file_id) throw new Error(data.error || "Failed to initialize upload");

            // 3. Encrypt & Upload Chunks one-by-one
            const key = await ZKAuth._importKey(encryptionKey);
            
            for (let i = 0; i < totalChunks; i++) {
                status.innerText = `Processing and uploading chunk ${i + 1}/${totalChunks}...`;
                
                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, file.size);
                const chunkData = await file.slice(start, end).arrayBuffer();
                
                // Encrypt chunk
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const encrypted = await window.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv },
                    key,
                    chunkData
                );
                
                const encryptedUint8 = new Uint8Array(encrypted);
                const chunkHex = ZKAuth._toHex(encryptedUint8);
                const chunkHash = await ZKAuth._hash(encryptedUint8);

                // Upload chunk
                const cfd = new FormData();
                cfd.append('action', 'upload_chunk');
                cfd.append('csrf_token', csrfToken);
                cfd.append('file_id', data.file_id);
                cfd.append('chunk_index', i);
                cfd.append('chunk_hash', chunkHash);
                cfd.append('chunk_data', chunkHex);
                cfd.append('chunk_iv', ZKAuth._toHex(iv));
                
                const cRes = await fetch('upload.php', { method: 'POST', body: cfd });
                const cData = await cRes.json();
                if (cData.error) throw new Error(cData.error);
                
                console.log(`Chunk ${i+1}/${totalChunks} uploaded successfully`);
            }

            status.innerText = "Upload complete!";
            fileInput.value = ""; // Clear input
            loadFiles();
        } catch (e) {
            console.error("Upload error:", e);
            status.innerText = "Upload failed: " + (e.message || "Unknown error");
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
                    <button onclick="deleteFile('${f.file_id_public}')" style="background-color: #d9534f; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">Delete</button>
                </td>
            </tr>`;
            list.innerHTML += row;
        }
    }

    async function deleteFile(publicId) {
        if (!confirm("Are you sure you want to delete this file forever?")) return;

        const status = document.getElementById('uploadStatus');
        status.innerText = "Deleting file...";

        try {
            const csrfToken = "<?= $_SESSION['csrf_token'] ?>";
            const fd = new FormData();
            fd.append('action', 'delete_file');
            fd.append('csrf_token', csrfToken);
            fd.append('file_id_public', publicId);

            const res = await fetch('upload.php', { method: 'POST', body: fd });
            const data = await res.json();

            if (data.status === 'success') {
                status.innerText = "File deleted successfully!";
                loadFiles(); // Refresh list
            } else {
                throw new Error(data.error || "Failed to delete file");
            }
        } catch (e) {
            console.error("Delete error:", e);
            status.innerText = "Delete failed: " + (e.message || "Unknown error");
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
        const status = document.getElementById('uploadStatus'); // Reusing uploadStatus for download feedback
        status.innerText = "Fetching file metadata...";

        try {
            const res = await fetch(`download.php?file_id_public=${publicId}`);
            if (!res.ok) throw new Error("Failed to fetch file info");
            const data = await res.json();
            
            // 1. Decrypt Metadata
            const encMeta = JSON.parse(data.metadata);
            const meta = await ZKAuth.decryptMetadata(encMeta.blob, encMeta.iv, encryptionKey);
            
            console.log("Downloading:", meta.name);
            status.innerText = `Downloading ${meta.name} (0/${data.chunks.length} chunks)...`;

            // 2. Decrypt Chunks one by one
            let decryptedChunks = [];
            for (let i = 0; i < data.chunks.length; i++) {
                const cInfo = data.chunks[i];
                status.innerText = `Downloading and decrypting chunk ${i + 1}/${data.chunks.length}...`;
                
                const cRes = await fetch(`download.php?action=get_chunk&file_id_public=${publicId}&chunk_index=${cInfo.chunk_index}`);
                if (!cRes.ok) throw new Error(`Failed to fetch chunk ${i}`);
                const chunkHex = await cRes.text();

                const dec = await ZKAuth.decryptChunk(chunkHex, cInfo.chunk_iv, encryptionKey);
                decryptedChunks.push(dec);
            }

            // 3. Reassemble and Download
            status.innerText = "Reassembling file...";
            const finalBlob = new Blob(decryptedChunks, { type: meta.type });
            const url = URL.createObjectURL(finalBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = meta.name;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            status.innerText = "Download complete!";
        } catch (e) {
            console.error(e);
            status.innerText = "Download failed: " + e.message;
        }
    }

    loadFiles();
  </script>
</body>
</html>