<?php
// api/contact.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Contact endpoint — queues the request immediately and responds,
 * then a background worker composes & sends the email (no attachments).
 *
 * Requires: name, email, subject, message (company + phone optional)
 * Subject in email: "Contact Form: <subject>"
 */

const QUEUE_DIR = __DIR__ . '/queue';

function is_windows(): bool {
  return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
}
function ensure_queue_dir(): void {
  if (!is_dir(QUEUE_DIR)) {
    @mkdir(QUEUE_DIR, 0700, true);
  }
  if (!is_dir(QUEUE_DIR) || !is_writable(QUEUE_DIR)) {
    json_fail('Server queue unavailable');
  }
}
function spawn_worker(string $jobPath): void {
  $php = PHP_BINARY ?: 'php';
  $script = __DIR__ . '/mail_worker.php';
  if (is_windows()) {
    $cmd = 'start /B "" ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($jobPath) . ' > NUL 2>&1';
  } else {
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($jobPath) . ' > /dev/null 2>&1 &';
  }
  @exec($cmd);
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

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$phone   = trim($data['phone']   ?? '');
$subject = trim($data['subject'] ?? '');
$message = trim($data['message'] ?? '');
$hp      = trim($data['website_honeypot'] ?? '');

if ($hp !== '') { echo json_encode(['ok'=>true]); exit; } // silently accept bots
if ($name === '' || $email === '' || $subject === '' || $message === '') {
  json_fail('Missing required fields');
}

$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

ensure_queue_dir();

$job = [
  'type'     => 'contact',
  'when'     => date('c'),
  'ip'       => $ip,
  'name'     => $name,
  'company'  => $company,
  'email'    => $email,
  'phone'    => $phone,
  'subject'  => $subject,
  'message'  => $message,
];
$jobPath = QUEUE_DIR . DIRECTORY_SEPARATOR . 'job_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.json';
if (@file_put_contents($jobPath, json_encode($job, JSON_UNESCAPED_SLASHES)) === false) {
  json_fail('Server queue write failed');
}
@chmod($jobPath, 0600);

spawn_worker($jobPath);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok'=>true,'message'=>'Accepted'], JSON_UNESCAPED_SLASHES);
