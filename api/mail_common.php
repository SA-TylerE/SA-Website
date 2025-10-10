<?php
// api/mail_common.php
declare(strict_types=1);

header('Content-Type: application/json');

// CORS for both domains (current and future)
$allowed = [
  'https://certifiedgeeksllc.net',
  'https://www.certifiedgeeksllc.net',
  'https://systemalternatives.net',
  'https://www.systemalternatives.net',
  'http://localhost:3000',
  'http://127.0.0.1'
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed, true)) {
  header("Access-Control-Allow-Origin: $origin");
  header("Vary: Origin");
  header("Access-Control-Allow-Headers: Content-Type");
  header("Access-Control-Allow-Methods: POST, OPTIONS");
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { exit; }

// --- CONFIG ---
// Use a verified domain for DMARC alignment:
const SMTP_HOST = 'mail.smtp2go.com';
const SMTP_PORT = 587; // STARTTLS
const SMTP_USER = 'sawebsite';
const SMTP_PASS = 'BzuQG1zQ3g4aIK9G';
const FROM_ADDRESS = 'no-reply@systemalternatives.net';

const HELP_DESK_TO = 'tylere@systemalternatives.net';
const CONTACT_TO   = 'tylere@systemalternatives.net';

// --- Helpers ---
function json_fail(string $msg, int $code = 400) {
  http_response_code($code);
  echo json_encode(['ok'=>false,'error'=>$msg], JSON_UNESCAPED_SLASHES);
  exit;
}
function body_json(): array {
  $raw = file_get_contents('php://input') ?: '';
  $data = json_decode($raw, true);
  if (!is_array($data)) json_fail('Invalid JSON body');
  return $data;
}

// --- PHPMailer bootstrap ---
require_once __DIR__.'/vendor/phpmailer/Exception.php';
require_once __DIR__.'/vendor/phpmailer/PHPMailer.php';
require_once __DIR__.'/vendor/phpmailer/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function send_mail_smtp2go(string $to, string $replyTo, string $subject, string $html, string $text, array $attachments = []): bool {
  $mail = new PHPMailer(true);
  try {
    $mail->isSMTP();
    $mail->Host       = SMTP_HOST;
    $mail->Port       = SMTP_PORT;
    $mail->SMTPAuth   = true;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // using TLS (enable OpenSSL)
    $mail->Username   = SMTP_USER;
    $mail->Password   = SMTP_PASS;

    $mail->setFrom(FROM_ADDRESS, 'SA Website');
    $mail->addAddress($to);
    if (filter_var($replyTo, FILTER_VALIDATE_EMAIL)) {
      $mail->addReplyTo($replyTo);
    }

    // Safe attachments (already validated in contact.php)
    foreach ($attachments as $att) {
      if (!empty($att['path']) && is_readable($att['path'])) {
        $mail->addAttachment($att['path'], $att['name'] ?? basename($att['path']));
      }
    }

    $mail->Subject = $subject;
    $mail->isHTML(true);
    $mail->Body    = $html;
    $mail->AltBody = $text;

    return $mail->send();
  } catch (Exception $e) {
    json_fail('Mailer error: '.$e->getMessage(), 500);
  }
  return false;
}