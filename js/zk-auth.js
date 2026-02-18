// Zero-Knowledge Auth Client
// Handles PBKDF2 Key Derivation and Auth Handshake

const ZKAuth = {
    // Configuration
    iterations: 310000, // OWASP 2023 Recommendation for PBKDF2-HMAC-SHA256
    hash: 'SHA-256',
    keyLength: 32, // 256 bits

    // 1. Generate Random Salt (Client-Side)
    generateSalt: () => {
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // 2. Derive Master Key from Password & Salt
    deriveKey: async (password, saltHex) => {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw", 
            enc.encode(password), 
            { name: "PBKDF2" }, 
            false, 
            ["deriveBits", "deriveKey"]
        );

        // Convert hex salt back to bytes
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        // Derive 64 bytes (32 for Auth, 32 for Encryption)
        const derivedBits = await window.crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: ZKAuth.iterations,
                hash: ZKAuth.hash
            },
            keyMaterial,
            512 // 64 bytes * 8 bits
        );

        return derivedBits;
    },

    // 3. Split Key into Auth Key and Encryption Key
    splitKey: async (derivedBits) => {
        const buffer = new Uint8Array(derivedBits);
        const authKeyBytes = buffer.slice(0, 32);
        const encKeyBytes = buffer.slice(32, 64);

        // Hash the Auth Key one more time before sending to server (Double Hashing)
        // This ensures even if the database is leaked, the "password" (AuthKey) is hashed.
        // And the server will hash it AGAIN (Triple Hashing concept).
        const authKeyHash = await window.crypto.subtle.digest('SHA-256', authKeyBytes);

        return {
            authKeyHex: Array.from(new Uint8Array(authKeyHash)).map(b => b.toString(16).padStart(2, '0')).join(''),
            encryptionKeyHex: Array.from(encKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('') // Keep this local!
        };
    },

    // Helper: Verify password strength client-side (redundant but good UX)
    checkStrength: (password) => {
        return password.length >= 12;
    },

    // --- NEW: Zero-Knowledge File Processing ---

    // 4. Encrypt Metadata (Name, Size, MIME)
    encryptMetadata: async (metadata, keyHex) => {
        const key = await ZKAuth._importKey(keyHex);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedMetadata = new TextEncoder().encode(JSON.stringify(metadata));
        
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encodedMetadata
        );

        return {
            blob: ZKAuth._toHex(new Uint8Array(encrypted)),
            iv: ZKAuth._toHex(iv)
        };
    },

    // 5. Encrypt File Chunks (AES-GCM)
    // Splits file into 5MB chunks (Standard for ZK)
    encryptFile: async (file, keyHex) => {
        const chunkSize = 5 * 1024 * 1024; // 5MB
        const key = await ZKAuth._importKey(keyHex);
        const chunks = [];
        const totalChunks = Math.ceil(file.size / chunkSize);

        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const data = await file.slice(start, end).arrayBuffer();
            
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                key,
                data
            );

            chunks.push({
                index: i,
                iv: ZKAuth._toHex(iv),
                data: ZKAuth._toHex(new Uint8Array(encrypted)),
                hash: await ZKAuth._hash(new Uint8Array(encrypted))
            });
        }
        return chunks;
    },

    // 6. Decrypt Metadata
    decryptMetadata: async (encryptedHex, ivHex, keyHex) => {
        const key = await ZKAuth._importKey(keyHex);
        const iv = ZKAuth._fromHex(ivHex);
        const data = ZKAuth._fromHex(encryptedHex);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        return JSON.parse(new TextDecoder().decode(decrypted));
    },

    // 7. Decrypt File Chunks
    decryptChunk: async (chunkHex, ivHex, keyHex) => {
        const key = await ZKAuth._importKey(keyHex);
        const iv = ZKAuth._fromHex(ivHex);
        const data = ZKAuth._fromHex(chunkHex);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        return decrypted;
    },

    // Internal Helpers
    _importKey: (hex) => {
        return window.crypto.subtle.importKey(
            "raw", 
            ZKAuth._fromHex(hex), 
            { name: "AES-GCM" }, 
            false, 
            ["encrypt", "decrypt"]
        );
    },

    _toHex: (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''),
    _fromHex: (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))),
    _hash: async (data) => {
        const hash = await window.crypto.subtle.digest('SHA-256', data);
        return ZKAuth._toHex(new Uint8Array(hash));
    }
};
