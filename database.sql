-- Zero-Knowledge Database Schema
-- Focus: Security, Salt Storage, Rate Limiting, and Verification

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    auth_verifier VARCHAR(255) NOT NULL, -- Hashed Auth Key (Server never sees raw password)
    salt VARCHAR(64) NOT NULL,           -- Unique per-user salt for client-side derivation
    
    -- Verification
    is_verified TINYINT(1) DEFAULT 0,
    verification_token VARCHAR(64),
    otp_expiry INT,

    -- Security & Rate Limiting
    login_attempts INT DEFAULT 0,
    last_attempt_time INT DEFAULT 0,
    lockout_until INT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(50), -- Can be NULL if username doesn't exist
    attempt_time INT NOT NULL,
    success TINYINT(1) DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    metadata_blob TEXT NOT NULL, -- Encrypted JSON (filename, size, type)
    total_chunks INT NOT NULL,
    file_id_public VARCHAR(64) UNIQUE NOT NULL, -- Random ID for sharing/access
    is_public TINYINT(1) DEFAULT 0, -- NEW: Allow public access
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_chunks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_id INT NOT NULL,
    chunk_index INT NOT NULL,
    chunk_hash VARCHAR(64) NOT NULL,
    chunk_iv VARCHAR(32) NOT NULL, -- AES-GCM IV (hex)
    storage_path VARCHAR(255) NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- Index for fast chunk retrieval
CREATE INDEX idx_file_chunks ON file_chunks(file_id, chunk_index);
