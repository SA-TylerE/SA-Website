<?php
// api/contact.php
declare(strict_types=1);

require_once __DIR__.'/mail_common.php';

/**
 * Contact form endpoint (no attachments)
 * - Accepts JSON or form-data
 * - Requires: name, email, phone, subject, message  (company optional)
 * - Immediately ACKs with {"ok":true} so the UI can show "Sent"
 * - Then continues email processing in the background
 */

function get_request_data(): array {
  $ctype = $_SERVER['CONTENT_TYPE'] ?? '';
  if (stripos($ctype, 'application/json') !== false) {
    $raw = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    if (!is_array($data)) json_fail('Invalid JSON body');
    return $data;
  }
  return $_POST;
}

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$phone   = trim($data['phone']   ?? '');
$subject = trim($data['subject'] ?? '');
$message = trim($data['message'] ?? '');
$hp      = trim($data['website_honeypot'] ?? ''); // spam trap

// Honeypot: quietly "succeed"
if ($hp !== '') { echo json_encode(['ok'=>true]); exit; }

// Validate
if ($name === '' || $email === '' || $phone === '' || $subject === '' || $message === '') {
  json_fail('Missing required fields');
}

// Prepare email content
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$htmlMessage  = nl2br($safe($message));
$emailSubject = 'Contact Form: ' . $subject;
$htmlHeader   = $safe($emailSubject);

$html = '
  <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
    <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
      <h2 style="margin:0 0 12px">'.$htmlHeader.'</h2>
      <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
        <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.$safe($name).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.$safe($company).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.$safe($email).'" style="color:#aa1e2e">'.$safe($email).'</a></td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Phone</td><td style="padding:6px 0;">'.$safe($phone).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.$safe($ip).'</td></tr>
      </table>
      <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
      <div>
        <div style="font-weight:700; margin:0 0 6px">Message</div>
        <div style="white-space:pre-wrap; line-height:1.5">'.$htmlMessage.'</div>
      </div>
    </div>
  </div>';

$text = $emailSubject."\n"
      . "From: $name\n"
      . "Company: $company\n"
      . "Email: $email\n"
      . "Phone: $phone\n"
      . "IP: $ip\n\n"
      . "$message\n";

/**
 * Early ACK (client sees "Sent"), then continue processing.
 * We rely on PHP-FPM's fastcgi_finish_request() when available.
 */
function early_ack_then_continue(array $payload = ['ok'=>true]) : void {
  // Ensure JSON header already set by mail_common.php; just echo payload
  echo json_encode($payload, JSON_UNESCAPED_SLASHES);
  echo "\n";
  // Flush and close client connection
  if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
  } else {
    // Generic fallback; not as strong but works decently
    @ob_end_flush();
    @flush();
  }
}

// Send early OK to the browser
early_ack_then_continue(['ok'=>true,'message'=>'Received']);

// === Background work continues here ===
ignore_user_abort(true); // keep going even if client navigates away

// Send email (no attachments on contact)
try {
  // PHPMailer errors inside send_mail_smtp2go() will be handled by json_fail()
  // but since we already finished the response, any output is discarded.
  send_mail_smtp2go(
    CONTACT_TO,   // destination from mail_common.php
    $email,       // reply-to
    $emailSubject,
    $html,
    $text
  );
} catch (Throwable $e) {
  // Just log; user already has ACK
  error_log('contact.php mail send error: '.$e->getMessage());
}

// Done (no further output)
exit;
