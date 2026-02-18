# SYFE - Secure Your Files Encrypted

SYFE is a high-performance, **Zero-Knowledge (ZK)** file storage and sharing platform. It ensures that your files are encrypted **before** they ever leave your browser, meaning the server never sees your raw data or your password.

## 🚀 Key Features

- **Zero-Knowledge Architecture:** All encryption and decryption happen client-side using the Web Crypto API (AES-GCM).
- **Huge File Support (1GB+):** Optimized chunked streaming allows for uploading and downloading massive files without crashing the browser memory.
- **Modern "Cyber" UI:** A sleek, dark-themed dashboard with glassmorphism effects and dynamic animations.
- **Secure Sharing:** Share files via unique links where the decryption key is passed in the URL fragment (`#`), ensuring it is never sent to the server.
- **Secure Deletion:** Deleting a file physically removes all encrypted shards from the server storage.
- **Test Mode:** Built-in development mode to bypass email verification for rapid prototyping.

## 🛡️ Security Architecture

1.  **Key Derivation:** PBKDF2-HMAC-SHA256 with 310,000 iterations (OWASP 2023) derives a 512-bit master key from your password and a unique salt.
2.  **Key Splitting:** The master key is split into:
    *   **Auth Key:** Hashed and sent to the server for authentication.
    *   **Encryption Key:** Kept strictly in `sessionStorage` for encrypting/decrypting data.
3.  **File Encryption:** Files are split into 1MB chunks, each encrypted with AES-256-GCM using a unique 96-bit IV.
4.  **Database Integrity:** The server only stores encrypted metadata, encrypted shards, and the hashed auth verifier.

## 🛠️ Installation

### Option 1: Docker (Recommended)
The easiest way to get SYFE running is using Docker Compose.

1.  Clone the repository.
2.  Copy `.env.example` to `.env`.
3.  Run the following command:
    ```bash
    docker compose up -d --build
    ```
4.  Access the application at `http://localhost:8080`.

### Option 2: Manual Setup
1.  **Server:** Apache/Nginx with PHP 8.2+ and `pdo_mysql` extension.
2.  **Database:** MySQL 8.0+. Import `database.sql` to initialize the schema.
3.  **Dependencies:** Install PHPMailer:
    ```bash
    git clone https://github.com/PHPMailer/PHPMailer.git vendor/PHPMailer
    ```
4.  **Storage:** Create `storage/chunks/` and ensure it is writeable by the web server.

## ⚙️ Configuration (`.env`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DB_HOST` | Database host | `db` |
| `DB_NAME` | Database name | `syfe_db` |
| `SERVER_PEPPER` | Secret string for additional hashing | `(Required)` |
| `TEST_MODE` | Set to `true` to bypass email verification | `false` |
| `SMTP_*` | SMTP settings for account verification | `(Optional)` |

## 📖 Usage

1.  **Register:** Create an account. In `TEST_MODE`, you will be logged in immediately.
2.  **Upload:** Select a file. It will be encrypted in 1MB chunks and streamed to the server.
3.  **Download:** Click "Download". Shards are fetched one-by-one, decrypted, and reassembled in your browser.
4.  **Share:** Mark a file as "Public" and copy the link. The link contains the key in the hash (`#`), keeping it private from the server logs.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
