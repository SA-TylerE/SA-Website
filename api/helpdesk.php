<?php
// api/helpdesk.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Minimal async queueing endpoint for Support (Helpdesk).
 * - Accepts multipart/form-data (attachments) or JSON
 * - Queues a job file under api/queue/
 * - Spawns api/mail_worker.php in the background on Ubuntu
 * - Logs to api/logs/app.log
 *
 * Requires dirs:
 *   api/queue (0700, writable by web user)
 *   api/logs  (0700, writable by web user)
 */

const QUEUE_DIR         = __DIR__ . '/queue';
const LOG_DIR           = __DIR__ . '/logs';
const LOG_FILE          = LOG_DIR . '/app.log';

const MAX_FILES         = 5;
const MAX_SIZE_BYTES    = 5 * 1024 * 1024; // 5 MB
const ALLOWED_EXT_REGEX = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';

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
    $line = '['.date('Y-m-d H:i:s').'] helpdesk.php: '.$msg.PHP_EOL;
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

function normalize_files_array(array $files): array {
  $out = [];
  if (is_array($files['name'] ?? null)) {
    foreach ($files['name'] as $i => $name) {
      $out[] = [
        'name'     => $name,
        'type'     => $files['type'][$i]      ?? '',
        'tmp_name' => $files['tmp_name'][$i]  ?? '',
        'error'    => $files['error'][$i]     ?? UPLOAD_ERR_NO_FILE,
        'size'     => (int)($files['size'][$i]?? 0),
      ];
    }
  } else {
    $out[] = [
      'name'     => $files['name']     ?? '',
      'type'     => $files['type']     ?? '',
      'tmp_name' => $files['tmp_name'] ?? '',
      'error'    => $files['error']    ?? UPLOAD_ERR_NO_FILE,
      'size'     => (int)($files['size']?? 0),
    ];
  }
  return $out;
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
  // Ubuntu: detach with nohup in the background
  $php = PHP_BINARY ?: '/usr/bin/php';
  $script = __DIR__ . '/mail_worker.php';
  $cmd = 'nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($jobPath) . ' >/dev/null 2>&1 &';
  @exec($cmd, $o, $r);
  qlog("spawn_worker: exec='$cmd' rc=$r");
  return true; // best-effort; worker logs will tell the truth
}

try {
  $data    = get_request_data();
  $name    = trim($data['name']    ?? '');
  $company = trim($data['company'] ?? '');
  $email   = trim($data['email']   ?? '');
  $issue   = trim($data['issue']   ?? '');
  $hp      = trim($data['website_honeypot'] ?? '');

  if ($hp !== '') { echo json_encode(['ok'=>true]); exit; }
  if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');

  $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

  // Stage attachments safely into queue/
  $staged = [];
  if (!empty($_FILES['attachments'])) {
    $flat = normalize_files_array($_FILES['attachments']);
    $flat = array_values(array_filter($flat, fn($f)=> ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
    if (count($flat) > MAX_FILES) json_fail('Too many files (max 5)');
    ensure_dir(QUEUE_DIR);

    foreach ($flat as $idx => $f) {
      if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;
      $nameBase = basename($f['name'] ?? 'file');
      if (!preg_match(ALLOWED_EXT_REGEX, $nameBase)) continue;
      $size = (int)($f['size'] ?? 0);
      if ($size > MAX_SIZE_BYTES) continue;
      if (empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) continue;

      $safeName = preg_replace('/[^A-Za-z0-9._-]+/', '_', $nameBase);
      $uniq = bin2hex(random_bytes(4));
      $dest = QUEUE_DIR . "/att_{$uniq}_{$safeName}";
      if (!@move_uploaded_file($f['tmp_name'], $dest)) continue;
      @chmod($dest, 0600);

      $staged[] = [
        'name'        => $safeName,
        'path'        => $dest,
        'size'        => $size,
        'client_type' => (string)($f['type'] ?? ''),
      ];
    }
  }

  $job = [
    'type'        => 'helpdesk',
    'when'        => date('c'),
    'ip'          => $ip,
    'name'        => $name,
    'company'     => $company,
    'email'       => $email,
    'issue'       => $issue,
    'attachments' => $staged,
  ];
  $jobPath = queue_write($job);
  spawn_worker($jobPath);

  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok'=>true,'message'=>'Accepted'], JSON_UNESCAPED_SLASHES);
} catch (\Throwable $e) {
  qlog('EXCEPTION: '.$e->getMessage());
  json_fail('Server error', 500);
}
