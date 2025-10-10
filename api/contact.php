<?php
// api/contact.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Contact form. Immediately acknowledges receipt to client,
 * then assembles + sends the email after flushing the HTTP response.
 * No attachments on Contact (by your latest spec).
 */

/* ------------- Utilities ------------- */
function json_fail(string $msg, int $code = 400): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok'=>false,'error'=>$msg], JSON_UNESCAPED_SLASHES);
  exit;
}

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

function respond_now_and_continue(array $payload = ['ok'=>true]): void {
  ignore_user_abort(true);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
  echo json_encode($payload, JSON_UNESCAPED_SLASHES);
  if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
    return;
  }
  header('Connection: close');
  $size = ob_get_length();
  if ($size === false) { $size = 0; }
  header("Content-Length: ".$size);
  @ob_end_flush();
  @flush();
  @ob_flush();
}
/* ------------------------------------ */

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$phone   = trim($data['phone']   ?? '');
$subject = trim($data['subject'] ?? '');
$message = trim($data['message'] ?? '');
$hp      = trim($data['website_honeypot'] ?? '');

if ($hp !== '') { respond_now_and_continue(['ok'=>true]); exit; }
if ($name === '' || $email === '' || $subject === '' || $message === '') {
  json_fail('Missing required fields');
}

/* Immediately ACK to the browser */
respond_now_and_continue(['ok'=>true, 'message'=>'Accepted']);

/* ===== Continue after flush: build + send ===== */
set_time_limit(180);

$ip   = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';
$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$htmlMessage = nl2br($safe($message));

$html = '
  <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
    <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
      <h2 style="margin:0 0 12px">Contact Form: '. $safe($subject) .'</h2>
      <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
        <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.$safe($name).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.$safe($company).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.$safe($email).'" style="color:#aa1e2e">'.$safe($email).'</a></td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Phone</td><td style="padding:6px 0;">'.($phone !== '' ? $safe($phone) : '<span style="color:#9aa0a6">n/a</span>').'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.$safe($ip).'</td></tr>
      </table>
      <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
      <div>
        <div style="font-weight:700; margin:0 0 6px">Message</div>
        <div style="white-space:pre-wrap; line-height:1.5">'.$htmlMessage.'</div>
      </div>
    </div>
  </div>';

$text = "Contact Form: $subject\n"
      . "From: $name\n"
      . "Company: $company\n"
      . "Email: $email\n"
      . "Phone: " . ($phone !== '' ? $phone : 'n/a') . "\n"
      . "IP: $ip\n\n"
      . "$message\n";

$subjectLine = "Contact Form: $subject";

try {
  send_mail_smtp2go(
    CONTACT_TO,   // techs@systemalternatives.net (in mail_common.php)
    $email,       // reply-to
    $subjectLine,
    $html,
    $text,
    []            // no attachments for Contact
  );
} catch (Throwable $e) {
  error_log("contact mail send error: ".$e->getMessage());
}

exit;
