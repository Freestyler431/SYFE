<?php
// OTP generation function
function generate_otp() {
    global $otp_length, $otp_type, $otp_case_sensitive;
    $characters = match ($otp_type) {
        'alpha'        => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'alphanumeric' => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        default        => '0123456789',
    };
    $otp = '';
    for ($i = 0; $i < $otp_length; $i++) {
        $otp .= $characters[random_int(0, strlen($characters) - 1)];
    }
    return $otp_case_sensitive ? $otp : strtolower($otp);
}

// CAPTCHA verification functions
function verify_captcha($url, $data) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        error_log('cURL error: ' . curl_error($ch));
        curl_close($ch);
        return null;
    }
    curl_close($ch);
    return json_decode($response);
}

function verify_recaptcha_v2($response, $secret_key) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];
    $decoded_response = verify_captcha($url, $data);
    return $decoded_response->success ?? false;
}

function verify_recaptcha_v3($response, $secret_key) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];
    $decoded_response = verify_captcha($url, $data);
    return ($decoded_response->success ?? false) && ($decoded_response->score >= 0.5);
}

function verify_hcaptcha($response, $secret_key) {
    $url = 'https://hcaptcha.com/siteverify';
    $data = [
        'secret' => $secret_key,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];
    $decoded_response = verify_captcha($url, $data);
    return $decoded_response->success ?? false;
}

// Send verification email
function send_verification_email($email, $otp) {
    global $verification_email_subject, $verification_email_message, $email_verification_type,
           $smtp_host, $smtp_port, $smtp_username, $smtp_password, $smtp_from,
           $sendmail_path;

    require_once 'PHPMailer/PHPMailer.php';
    require_once 'PHPMailer/SMTP.php';
    require_once 'PHPMailer/Exception.php';

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    try {
        switch ($email_verification_type) {
            case 'smtp':
                $mail->isSMTP();
                $mail->Host       = $smtp_host;
                $mail->Port       = $smtp_port;
                $mail->SMTPAuth   = true;
                $mail->Username   = $smtp_username;
                $mail->Password   = $smtp_password;
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                break;
            case 'sendmail':
                $mail->isSendmail();
                $mail->Sendmail = $sendmail_path;
                break;
            default:
                return false;
        }
        $mail->setFrom($smtp_from);
        $mail->addAddress($email);
        $mail->Subject = $verification_email_subject;
        $mail->Body    = $verification_email_message . $otp;
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}
?>