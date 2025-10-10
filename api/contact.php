<?php
// api/contact.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Minimal async queueing endpoint for Contact (no attachments).
 * - Queues a job file under api/queue/
 * - Spawns api/mail_worker.php
 * - Logs to api/logs/app.log
 */

const QUEUE_DIR = __DIR__ . '/queue';
const LOG_DIR   = __DIR__ . '/logs';
const LOG_FILE  = LOG_DIR . '/app.log';

function ensure_dir(string $dir): void {
  if (!is_dir($dir)) @mkdir($dir, 0700, true);
  if (is_dir($dir)) @chmod($dir, 0700);
  if (!is_dir($dir) || !is_writable($dir)) {
    throw new RuntimeException("Directory not writable: $dir");
  }
}

function qlog(string $msg): void {
  try {
    ensure_dir(LOG_DIR);
    $line = '['.date('Y-m-d H:i:s').'] contact.php: '.$msg.PHP_EOL;
    @file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
  } catch (\Throwable $e) { /* ignore */ }
}

function json_fail(string $msg, int $code = 400): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok'=>false, 'error'=>$msg], JSON_UNESCAPED_SLASHES);
  qlog("FAIL $code: $msg");
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

function queue_write(array $job): string {
  ensure_dir(QUEUE_DIR);
  $jobPath = QUEUE_DIR . '/job_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.json';
  if (@file_put_contents($jobPath, json_encode($job, JSON_UNESCAPED_SLASHES)) === false) {
    throw new RuntimeException('Queue write failed');
  }
  @chmod($jobPath, 0600);
  qlog("Queued job: $jobPath");
  return $jobPath;
}

function spawn_worker(string $jobPath): bool {
  $php = PHP_BINARY ?: '/usr/bin/php';
  $script = __DIR__ . '/mail_worker.php';
  $cmd = 'nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($jobPath) . ' >/dev/null 2>&1 &';
  @exec($cmd, $o, $r);
  qlog("spawn_worker: exec='$cmd' rc=$r");
  return true;
}

try {
  $data    = get_request_data();
  $name    = trim($data['name']    ?? '');
  $company = trim($data['company'] ?? '');
  $email   = trim($data['email']   ?? '');
  $phone   = trim($data['phone']   ?? '');
  $subject = trim($data['subject'] ?? '');
  $message = trim($data['message'] ?? '');
  $hp      = trim($data['website_honeypot'] ?? '');

  if ($hp !== '') { echo json_encode(['ok'=>true]); exit; }
  if ($name === '' || $email === '' || $subject === '' || $message === '') {
    json_fail('Missing required fields');
  }

  $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

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
  $jobPath = queue_write($job);
  spawn_worker($jobPath);

  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok'=>true,'message'=>'Accepted'], JSON_UNESCAPED_SLASHES);
} catch (\Throwable $e) {
  qlog('EXCEPTION: '.$e->getMessage());
  json_fail('Server error', 500);
}
