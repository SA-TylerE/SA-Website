<?php
// api/helpdesk.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Helpdesk (Support) endpoint — queues the request immediately and responds,
 * then a background worker scans attachments & sends the email.
 *
 * Requires: name, email, issue (company optional).
 * Subject in email: "Support Form: <derived>" (worker composes final).
 */

const QUEUE_DIR          = __DIR__ . '/queue';
const MAX_FILES          = 5;
const MAX_SIZE_BYTES     = 5 * 1024 * 1024; // 5 MB
const ALLOWED_EXT_REGEX  = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';
const ALLOWED_MIME       = [
  'image/png','image/jpeg','application/pdf','text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/csv'
];

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
    // Windows: detach with 'start /B'
    $cmd = 'start /B "" ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($jobPath) . ' > NUL 2>&1';
  } else {
    // Linux: background with &
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($jobPath) . ' > /dev/null 2>&1 &';
  }
  // Fire and forget
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

// Normalize $_FILES[...] to a simple array (single/multiple safe)
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

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$issue   = trim($data['issue']   ?? '');
$hp      = trim($data['website_honeypot'] ?? '');

if ($hp !== '') { echo json_encode(['ok'=>true]); exit; } // silently accept bots
if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');

$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

ensure_queue_dir();

// Stage attachments to queue dir
$staged = []; // each: ['name','path','size','client_type']
if (!empty($_FILES['attachments'])) {
  $flat = normalize_files_array($_FILES['attachments']);
  $flat = array_values(array_filter($flat, fn($f)=> ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
  if (count($flat) > MAX_FILES) json_fail('Too many files (max 5)');

  foreach ($flat as $idx => $f) {
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
      json_fail('Upload error on file '.$idx);
    }
    $nameBase = basename($f['name'] ?? 'file');
    if (!preg_match(ALLOWED_EXT_REGEX, $nameBase)) { continue; }
    $size = (int)($f['size'] ?? 0);
    if ($size > MAX_SIZE_BYTES) { continue; }
    if (empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) { continue; }

    $safeName = preg_replace('/[^A-Za-z0-9._-]+/', '_', $nameBase);
    // unique filename in queue
    $uniq = bin2hex(random_bytes(4));
    $dest = QUEUE_DIR . DIRECTORY_SEPARATOR . "att_{$uniq}_" . $safeName;
    if (!@move_uploaded_file($f['tmp_name'], $dest)) { continue; }
    @chmod($dest, 0600);
    $staged[] = [
      'name'        => $safeName,
      'path'        => $dest,
      'size'        => $size,
      'client_type' => (string)($f['type'] ?? ''),
    ];
  }
}

// Create job file
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
$jobPath = QUEUE_DIR . DIRECTORY_SEPARATOR . 'job_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.json';
if (@file_put_contents($jobPath, json_encode($job, JSON_UNESCAPED_SLASHES)) === false) {
  json_fail('Server queue write failed');
}
@chmod($jobPath, 0600);

// Spawn worker & ACK immediately
spawn_worker($jobPath);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok'=>true,'message'=>'Accepted'], JSON_UNESCAPED_SLASHES);
