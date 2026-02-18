<?php
// Legacy utils wrapper for backward compatibility
require_once 'utils/security.php';

// OTP Generation
function generate_otp() {
    return bin2hex(random_bytes(3)); // 6 hex chars
}

// Email function using PHPMailer
function send_verification_email($email, $otp) {
    global $smtp_host, $smtp_port, $smtp_username, $smtp_password, $smtp_from, $test_mode;
    
    if ($test_mode) {
        error_log("TEST MODE: Verification code for $email is: $otp");
        return true;
    }
    
    require_once __DIR__ . '/vendor/PHPMailer/src/Exception.php';
    require_once __DIR__ . '/vendor/PHPMailer/src/PHPMailer.php';
    require_once __DIR__ . '/vendor/PHPMailer/src/SMTP.php';

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host       = $smtp_host;
        $mail->SMTPAuth   = true;
        $mail->Username   = $smtp_username;
        $mail->Password   = $smtp_password;
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = $smtp_port;

        $mail->setFrom($smtp_from, 'SYFE Secure');
        $mail->addAddress($email);

        $mail->isHTML(true);
        $mail->Subject = 'Verify your Secure Account';
        $mail->Body    = "Your verification code is: <b>$otp</b><br>This code expires in 10 minutes.";
        $mail->AltBody = "Your verification code is: $otp";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Message could not be sent. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
}
?>