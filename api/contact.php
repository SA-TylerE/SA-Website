<?php
// api/contact.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Contact form endpoint
 * - Accepts application/json or form-data (no attachments)
 * - Requires: name, company, email, subject, message
 * - Adds "Contact Form: <subject>" prefix
 * - Uses "SA Website" as sender name (set in mail_common.php)
 */

function get_request_data(): array {
  $ctype = $_SERVER['CONTENT_TYPE'] ?? '';
  if (stripos($ctype, 'application/json') !== false) {
    $raw = file_get_contents('php://input') ?: '';
    $data = json_decode($raw, true);
    if (!is_array($data)) json_fail('Invalid JSON body');
    return $data;
  }
  // form-data / x-www-form-urlencoded
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

// Honeypot: quietly succeed for bots
if ($hp !== '') { echo json_encode(['ok'=>true]); exit; }

if ($name === '' || $email === '' || $subject === '' || $message === '' || $phone === '') {
  json_fail('Missing required fields');
}

$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$htmlMessage = nl2br($safe($message));

$emailSubject = 'Contact Form: ' . $subject;     // prefix
$htmlHeader   = $safe($emailSubject);

// Build HTML
$html = '
  <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
    <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
      <h2 style="margin:0 0 12px">'.$htmlHeader.'</h2>
      <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
        <tr>
          <td style="padding:6px 0; font-weight:700; width:120px;">From</td>
          <td style="padding:6px 0;">'.$safe($name).'</td>
        </tr>
        <tr>
          <td style="padding:6px 0; font-weight:700;">Company</td>
          <td style="padding:6px 0;">'.$safe($company).'</td>
        </tr>
        <tr>
          <td style="padding:6px 0; font-weight:700;">Email</td>
          <td style="padding:6px 0;"><a href="mailto:'.$safe($email).'" style="color:#aa1e2e">'.$safe($email).'</a></td>
        </tr>
        <tr>
          <td style="padding:6px 0; font-weight:700;">Phone</td>
          <td style="padding:6px 0;">'.($phone !== '' ? $safe($phone) : '<span style="color:#9aa0a6">n/a</span>').'</td>
        </tr>
        <tr>
          <td style="padding:6px 0; font-weight:700;">IP</td>
          <td style="padding:6px 0;">'.$safe($ip).'</td>
        </tr>
      </table>
      <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
      <div>
        <div style="font-weight:700; margin:0 0 6px">Message</div>
        <div style="white-space:pre-wrap; line-height:1.5">'.$htmlMessage.'</div>
      </div>
    </div>
  </div>';

// Plain text
$text = $emailSubject."\n"
      . "From: $name\n"
      . "Company: $company\n"
      . "Email: $email\n"
      . "Phone: " . ($phone !== '' ? $phone : 'n/a') . "\n"
      . "IP: $ip\n\n"
      . "$message\n";

// Send (no attachments for contact)
send_mail_smtp2go(
  CONTACT_TO,     // e.g., techs@systemalternatives.net
  $email,         // reply-to
  $emailSubject,
  $html,
  $text
);

echo json_encode(['ok'=>true,'message'=>'Sent to team'], JSON_UNESCAPED_SLASHES);
