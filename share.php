<?php
require_once 'config.php';
session_start();
// Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: no-referrer");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Shared File - SYFE</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="js/zk-auth.js"></script>
</head>
<body>
    <div class="container share-card">
        <h1>Zero-Knowledge Shared File</h1>
        <p>This file is encrypted and can only be decrypted locally by you.</p>
        
        <div id="loading" style="display:none;" class="loading">Fetching encrypted shards...</div>
        <div id="decrypting" style="display:none;" class="loading">Decrypting and reassembling...</div>
        
        <div id="password-form" style="display:none;">
            <p style="font-size: 0.9rem; margin-bottom: 1rem;">Enter the decryption password to unlock:</p>
            <div class="form-field">
                <input type="password" id="share-password" placeholder="Encryption Password">
            </div>
            <button onclick="startSharedDownload()" class="btn-primary">Unlock & Download</button>
        </div>

        <div id="error" style="color:var(--danger); margin-top: 1rem; font-size: 0.9rem;"></div>
    </div>

    <script>
        // 1. Check if Key is in URL Fragment (#)
        // URL Format: share.php?id=PUBLIC_ID#KEY_HEX:SALT_HEX
        let publicId = new URLSearchParams(window.location.search).get('id');
        let fragment = window.location.hash.substring(1); // Remove #
        
        // SECURITY: Wipe the key from the URL bar immediately
        if (fragment) {
             history.replaceState(null, null, 'share.php?id=' + publicId);
        }
        
        if (!publicId) {
            document.getElementById('error').innerText = "Invalid Share Link.";
        } else {
            if (fragment) {
                // Key is in the URL - Auto Decrypt
                startSharedDownload(fragment);
            } else {
                // No key in URL - Prompt for Password
                document.getElementById('password-form').style.display = 'block';
            }
        }

        async function startSharedDownload(providedKeyInfo = null) {
            let keyHex = "";
            if (providedKeyInfo) {
                keyHex = providedKeyInfo;
            } else {
                const pass = document.getElementById('share-password').value;
                if (!pass) return;
                // Note: For password derivation, we'd need the salt. 
                // Since this is a ZK app, the salt would ideally be stored in metadata (if metadata is not encrypted)
                // or passed in the hash fragment.
            }

            document.getElementById('password-form').style.display = 'none';
            document.getElementById('loading').style.display = 'block';
            document.getElementById('loading').innerText = "Fetching file metadata...";

            try {
                const res = await fetch(`download.php?action=public_get&file_id_public=${publicId}`);
                if (!res.ok) throw new Error("File not found or private.");
                const data = await res.json();

                // Decrypt Metadata
                const encMeta = JSON.parse(data.metadata);
                const meta = await ZKAuth.decryptMetadata(encMeta.blob, encMeta.iv, keyHex);
                
                // Update UI with Filename
                document.querySelector('h1').innerText = meta.name;
                document.title = `${meta.name} - Secure Share`;

                document.getElementById('loading').style.display = 'none';
                document.getElementById('decrypting').style.display = 'block';
                document.getElementById('decrypting').innerText = `Downloading and decrypting ${meta.name} (0/${data.chunks.length})...`;

                // Decrypt Chunks one by one
                let decryptedChunks = [];
                for (let i = 0; i < data.chunks.length; i++) {
                    const cInfo = data.chunks[i];
                    document.getElementById('decrypting').innerText = `Downloading and decrypting chunk ${i + 1}/${data.chunks.length}...`;
                    
                    const cRes = await fetch(`download.php?action=get_chunk&file_id_public=${publicId}&chunk_index=${cInfo.chunk_index}`);
                    if (!cRes.ok) throw new Error(`Failed to fetch chunk ${i}`);
                    const chunkHex = await cRes.text();

                    const dec = await ZKAuth.decryptChunk(chunkHex, cInfo.chunk_iv, keyHex);
                    decryptedChunks.push(dec);
                }

                // Reassemble and Download
                document.getElementById('decrypting').innerText = "Reassembling and downloading...";
                const finalBlob = new Blob(decryptedChunks, { type: meta.type });
                const url = URL.createObjectURL(finalBlob);
                const a = document.createElement('a');
                a.href = url;
                a.download = meta.name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                document.getElementById('decrypting').innerText = "Download Successful!";
            } catch (e) {
                document.getElementById('error').innerText = "Decryption Failed. Invalid Key or Password.";
                document.getElementById('loading').style.display = 'none';
                document.getElementById('decrypting').style.display = 'none';
                if (!providedKeyInfo) document.getElementById('password-form').style.display = 'block';
                console.error(e);
            }
        }
    </script>
</body>
</html>