<?php
// MySQL Server configuration
$mysql_host = '';
$mysql_user = '';
$mysql_password = '';
$mysql_database = '';

// Option to require login
$require_login = true;

// Required password strength
$password_strength = 'strong'; // Options: 'weak', 'medium', 'strong', 'custom'
$password_custom_length = 16; // Required password length for 'custom' password strength

// Session max lifetime in hours
$session_max_lifetime = 24;

// Session cookie lifetime in hours
$session_cookie_lifetime = 24;

// Verification method options: 'none', 'email', 'recaptcha_v2', 'recaptcha_v3', 'hcaptcha'
$verification_method = 'none';
$email_verification_type = 'smtp'; // Options: 'smtp', 'imap', 'pop3', 'sendmail'

// Email verification configuration
$verification_email_subject = 'Email Verification';
$verification_email_message = 'Enter The provided code to verify your email: ';

// SMTP Server configuration
$smtp_host = 'smtp.yourdomain.com';
$smtp_port = 587;
$smtp_username = '';
$smtp_password = '';
$smtp_from = '';

// Email Server configuration via IMAP
$imap_host = 'imap.yourdomain.com';
$imap_port = 993;
$imap_username = '';
$imap_password = '';
$imap_from = '';

// Email Server configuration via POP3
$pop3_host = 'pop3.yourdomain.com';
$pop3_port = 995;
$pop3_username = '';
$pop3_password = '';
$pop3_from = '';

// Email Server configuration via Sendmail
$sendmail_path = '/usr/sbin/sendmail';

// OTP Configuration
$otp_length = 6;
$otp_expiry_minutes = 10;
$otp_type = 'numeric'; // Options: 'numeric', 'alpha', 'alphanumeric'
$otp_case_sensitive = false;
$otp_max_attempts = 3;

// reCaptcha v2 configuration
$recaptcha_v2_site_key = 'your_recaptcha_v2_site_key';
$recaptcha_v2_secret_key = 'your_recaptcha_v2_secret_key';

// reCaptcha v3 configuration
$recaptcha_v3_site_key = 'your_recaptcha_v3_site_key';
$recaptcha_v3_secret_key = 'your_recaptcha_v3_secret_key';

// hCaptcha configuration
$hcaptcha_site_key = 'your_hcaptcha_site_key';
$hcaptcha_secret_key = 'your_hcaptcha_secret_key';
?>