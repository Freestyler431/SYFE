<?php
// MySQL Server configuration, note that the Port is set to 3306!
$mysql_host = 'localhost';
$mysql_user = '';
$mysql_password = '';
$mysql_database = '';

// ----------------------- Seesion/Login options ---------------------

// Option to require login
$require_login = true;

// Required password strength
$password_strength = 'strong'; // Options: 'weak', 'medium', 'strong', 'custom'
$password_custom_length = 16; // Required password length for 'custom' password strength

// Session max lifetime in hours
$session_max_lifetime = 24;

// Session cookie lifetime in hours
$session_cookie_lifetime = 24;


// ----------------------- Registration options -----------------------

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
$smtp_from = 'syfe-noreply@example.com';

// --------------------------------------------------------------------

// Email Server configuration via Sendmail
$sendmail_path = '/usr/sbin/sendmail';

// OTP Configuration
$otp_length = 6;
$otp_expiry_minutes = 10;
$otp_type = 'numeric'; // Options: 'numeric', 'alpha', 'alphanumeric'
$otp_case_sensitive = false;
$otp_max_attempts = 3;

// Note: The Captcha-Keys are tesing keys and should be replaced with your own keys, The test-keys will always return a success response!

// reCaptcha v2 configuration
$recaptcha_v2_site_key = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
$recaptcha_v2_secret_key = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

// reCaptcha v3 configuration
$recaptcha_v3_site_key = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
$recaptcha_v3_secret_key = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

// hCaptcha configuration
$hcaptcha_site_key = '10000000-ffff-ffff-ffff-000000000001';
$hcaptcha_secret_key = '0x0000000000000000000000000000000000000000';
?>