<?php
// api/helpdesk.php
declare(strict_types=1);

/**
 * Fast-ACK helpdesk endpoint:
 *  - Validates fields & persists uploaded files to a per-request folder
 *  - Immediately returns JSON { ok:true, id } to the client
 *  - After the connection is closed, scans attachments (ClamAV) and emails via send_mail_smtp2go()
 *  - Logs everything to api/logs/helpdesk/YYYY-MM-DD/<id>.json
 *
 * IMPORTANT:
 *  - Ensure this file begins at column 1 with "<?php" (no BOM/whitespace before it).
 *  - If mail_common.php ever prints anything (echo/var_dump), it will break the JSON ACK.
 */

///////////////////////
// BOOTSTRAP + GUARDS
///////////////////////

ini_set('display_errors', '0');                   // never print errors to client
error_reporting(E_ALL);

$ROOT = __DIR__;
$DATE = date('Y-m-d');

// Ensure logging paths exist and capture PHP warnings/notices to a file
$LOG_DIR = $ROOT . '/logs/helpdesk/' . $DATE;
$ERR_LOG = $LOG_DIR . '/php_errors.log';
function ensure_dir(string $p): void { if (!is_dir($p)) @mkdir($p, 0775, true); }
ensure_dir($LOG_DIR);
ini_set('log_errors', '1');
ini_set('error_log', $ERR_LOG);

// Convert all PHP errors to exceptions we can catch (prevents accidental output)
set_error_handler(function($severity, $message, $file, $line){
  // Respect @-silence operator
  if (!(error_reporting() & $severity)) return false;
  throw new ErrorException($message, 0, $severity, $file, $line);
});

// Start fresh output buffering so we control exactly what goes to the client
while (ob_get_level()) { ob_end_clean(); }
ob_start();

// Include mailer (must not echo!)
require_once $ROOT . '/mail_common.php'; // must not print anything

///////////////////////
// SMALL HELPERS
///////////////////////

function json_fail(string $msg, int $code = 400): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  // reset output buffer to ensure only JSON goes out
  while (ob_get_level()) { ob_end_clean(); }
  echo json_encode(['ok'=>false,'error'=>$msg], JSON_UNESCAPED_SLASHES);
  exit;
}
function write_json_file(string $path, array $data): void {
  ensure_dir(dirname($path));
  @file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function normalize_files_array(array $files): array {
  $out = [];
  if (is_array($files['name'] ?? null)) {
    foreach ($files['name'] as $i => $name) {
      $out[] = [
        'name'     => (string)($files['name'][$i] ?? ''),
        'type'     => (string)($files['type'][$i] ?? ''),
        'tmp_name' => (string)($files['tmp_name'][$i] ?? ''),
        'error'    => (int)($files['error'][$i] ?? UPLOAD_ERR_NO_FILE),
        'size'     => (int)($files['size'][$i] ?? 0),
      ];
    }
  } else {
    $out[] = [
      'name'     => (string)($files['name'] ?? ''),
      'type'     => (string)($files['type'] ?? ''),
      'tmp_name' => (string)($files['tmp_name'] ?? ''),
      'error'    => (int)($files['error'] ?? UPLOAD_ERR_NO_FILE),
      'size'     => (int)($files['size'] ?? 0),
    ];
  }
  return $out;
}
function detect_mime_safely(string $tmpPath, string $name): string {
  if (class_exists('finfo')) {
    $fi = new finfo(FILEINFO_MIME_TYPE);
    $m  = $fi->file($tmpPath);
    if (is_string($m) && $m !== '') return $m;
  }
  if (function_exists('mime_content_type')) {
    $m = mime_content_type($tmpPath);
    if (is_string($m) && $m !== '') return $m;
  }
  $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
  $map = [
    'png'=>'image/png','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','pdf'=>'application/pdf',
    'txt'=>'text/plain','log'=>'text/plain','doc'=>'application/msword',
    'docx'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xlsx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','csv'=>'text/csv'
  ];
  return $map[$ext] ?? 'application/octet-stream';
}
function antivirus_scan_detail(string $path): array {
  $cands = [];
  foreach (['/usr/bin/clamdscan' => '--no-summary --fdpass', '/usr/bin/clamscan' => '--no-summary'] as $bin=>$opts) {
    if (is_executable($bin)) $cands[] = [$bin, $opts, basename($bin)];
  }
  if (!$cands) return ['status'=>'unavailable','engine'=>null,'code'=>2,'stdout'=>'','stderr'=>'no scanner'];
  foreach ($cands as [$bin,$opts,$engine]) {
    $cmd = $bin.' '.$opts.' '.escapeshellarg($path).' 2>&1';
    $out = []; $rc = 0; @exec($cmd, $out, $rc);
    $stdout = implode("\n", $out);
    if ($rc === 0) return ['status'=>'clean',    'engine'=>$engine,'code'=>$rc,'stdout'=>$stdout,'stderr'=>''];
    if ($rc === 1) return ['status'=>'infected', 'engine'=>$engine,'code'=>$rc,'stdout'=>$stdout,'stderr'=>''];
    $last = end($cands);
    if ($bin === $last[0]) return ['status'=>'error','engine'=>$engine,'code'=>$rc,'stdout'=>$stdout,'stderr'=>'rc!=0'];
  }
  return ['status'=>'error','engine'=>null,'code'=>2,'stdout'=>'','stderr'=>'scan failed'];
}

///////////////////////
// REQUEST INTAKE
///////////////////////

try {
  if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') json_fail('Method not allowed', 405);

  // Honeypot: accept quietly (keeps bots “happy”)
  if (trim((string)($_POST['website_honeypot'] ?? '')) !== '') {
    header('Content-Type: application/json; charset=utf-8');
    while (ob_get_level()) { ob_end_clean(); }
    echo json_encode(['ok'=>true], JSON_UNESCAPED_SLASHES);
    exit;
  }

  $name    = trim((string)($_POST['name'] ?? ''));
  $company = trim((string)($_POST['company'] ?? ''));
  $email   = trim((string)($_POST['email'] ?? ''));
  $issue   = trim((string)($_POST['issue'] ?? ''));
  if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');
  if (!filter_var($email, FILTER_VALIDATE_EMAIL))      json_fail('Invalid email');

  // Per-request workspace (make uploads durable before ACK)
  $reqId     = date('Ymd_His') . '_' . bin2hex(random_bytes(3));
  $QUEUE_DIR = $ROOT . '/queue/' . $reqId;
  $FILES_DIR = $QUEUE_DIR . '/files';
  ensure_dir($FILES_DIR);

  $meta = [
    'id'   => $reqId,
    'time' => date('c'),
    'ip'   => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '',
    'ua'   => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'fields' => ['name'=>$name,'company'=>$company,'email'=>$email],
    'files'  => [],
  ];

  // Intake files (limit + type/mime checks)
  $MAX_FILES   = 5;
  $MAX_SIZE    = 5 * 1024 * 1024;
  $ALLOWED_EXT = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';
  $ALLOWED_MIME= [
    'image/png','image/jpeg','application/pdf','text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','text/csv'
  ];

  $stored = [];
  if (!empty($_FILES['attachments'])) {
    $flat = normalize_files_array($_FILES['attachments']);
    $nonEmpty = array_values(array_filter($flat, fn($f)=> (int)($f['error']??UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
    if (count($nonEmpty) > $MAX_FILES) json_fail("Too many files (max $MAX_FILES)");

    $i = 0;
    foreach ($flat as $f) {
      if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) continue;
      if ($f['error'] !== UPLOAD_ERR_OK || empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) {
        $meta['files'][] = ['name'=>$f['name'] ?? 'file','status'=>'upload_error','code'=>$f['error']];
        continue;
      }
      $nameF = $f['name'] ?? 'file';
      $sizeF = (int)($f['size'] ?? 0);
      if ($sizeF > $MAX_SIZE) { $meta['files'][] = ['name'=>$nameF,'status'=>'too_large','size'=>$sizeF]; continue; }
      if (!preg_match($ALLOWED_EXT, $nameF)) { $meta['files'][] = ['name'=>$nameF,'status'=>'bad_type']; continue; }
      $mime = detect_mime_safely($f['tmp_name'], $nameF);
      if (!in_array($mime, $ALLOWED_MIME, true)) { $meta['files'][] = ['name'=>$nameF,'status'=>'mime_reject','mime'=>$mime]; continue; }

      $clean = preg_replace('/[^A-Za-z0-9._-]+/', '_', basename($nameF));
      $dest  = $FILES_DIR . '/' . sprintf('%02d_', $i++) . $clean;
      if (@move_uploaded_file($f['tmp_name'], $dest)) {
        $stored[] = ['name'=>$nameF,'path'=>$dest,'size'=>$sizeF,'mime'=>$mime];
        $meta['files'][] = ['name'=>$nameF,'status'=>'received','stored'=>$dest,'size'=>$sizeF,'mime'=>$mime];
      } else {
        $meta['files'][] = ['name'=>$nameF,'status'=>'move_failed'];
      }
    }
  }

  // Intake snapshot (helps debug early failures)
  write_json_file($QUEUE_DIR.'/intake.json', ['meta'=>$meta, 'issue_len'=>strlen($issue)]);

  // === FAST ACK (clean buffer, send only JSON) ===
  header('Content-Type: application/json; charset=utf-8');
  while (ob_get_level()) { ob_end_clean(); }
  echo json_encode(['ok'=>true,'id'=>$reqId], JSON_UNESCAPED_SLASHES);

  // Detach client
  if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
  } else {
    ignore_user_abort(true);
    @flush();
  }

  ///////////////////////
  // BACKGROUND WORK
  ///////////////////////

  // Scan all stored files
  $scan = [];
  $attachments = [];
  foreach ($stored as $f) {
    $res = antivirus_scan_detail($f['path']);
    $scan[] = [
      'name'=>$f['name'],'size'=>$f['size'],'mime'=>$f['mime'],
      'av'=>$res['status'],'engine'=>$res['engine'],'code'=>$res['code']
    ];
    if ($res['status'] === 'clean') {
      $attachments[] = ['path'=>$f['path'], 'name'=>basename($f['path'])];
    } else {
      error_log("AV blocked: {$f['name']} status={$res['status']} engine={$res['engine']} code={$res['code']}");
    }
  }

  // Build email
  $ip    = $meta['ip'];
  $hdr   = 'Support Form: ' . (mb_substr(preg_replace('/\s+/', ' ', $issue), 0, 80) ?: '(no subject)');
  $safe  = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  $html  = '
    <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#231f20">
      <div style="padding:16px 18px;border:1px solid #e6e6e6;border-radius:12px">
        <h2 style="margin:0 0 12px">'. $safe($hdr) .'</h2>
        <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%;border-collapse:collapse;margin:0 0 12px">
          <tr><td style="padding:6px 0;font-weight:700;width:120px">From</td><td style="padding:6px 0">'. $safe($name) .'</td></tr>
          <tr><td style="padding:6px 0;font-weight:700">Company</td><td style="padding:6px 0">'. $safe($company) .'</td></tr>
          <tr><td style="padding:6px 0;font-weight:700">Email</td><td style="padding:6px 0"><a href="mailto:'. $safe($email) .'">'. $safe($email) .'</a></td></tr>
          <tr><td style="padding:6px 0;font-weight:700">IP</td><td style="padding:6px 0">'. $safe($ip) .'</td></tr>
          <tr><td style="padding:6px 0;font-weight:700">Request ID</td><td style="padding:6px 0">'. $safe($reqId) .'</td></tr>
        </table>
        <div style="border-top:1px solid #e6e6e6;margin:10px 0 12px"></div>
        <div><div style="font-weight:700;margin:0 0 6px">Issue</div>
             <div style="white-space:pre-wrap;line-height:1.5">'. nl2br($safe($issue)) .'</div></div>
      </div>
    </div>';

  $text = $hdr."\nFrom: $name\nCompany: $company\nEmail: $email\nIP: $ip\nRequest ID: $reqId\n\n$issue\n";

  if ($scan) {
    $html .= '<div style="height:10px"></div>'
           . '<div style="padding:12px;border:1px solid #e6e6e6;border-radius:10px;background:#fafafa">'
           . '<div style="font-weight:800;margin:0 0 8px;color:#58595b">Attachment scan report</div>'
           . '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:0.95rem">'
           . '<tr><th align="left">File</th><th align="left">Size</th><th align="left">MIME</th><th align="left">AV</th></tr>';
    foreach ($scan as $r) {
      $sizeKB = number_format($r['size']/1024,1).' KB';
      $av = $r['av'].($r['engine'] ? ' ('.$r['engine'].')' : '').(isset($r['code']) ? ' #'.$r['code'] : '');
      $html .= '<tr><td>'.htmlspecialchars($r['name']).'</td><td>'.$sizeKB.'</td><td>'.htmlspecialchars((string)$r['mime']).'</td><td>'.htmlspecialchars($av).'</td></tr>';
    }
    $html .= '</table></div>';

    $text .= "\n--- Attachment scan report ---\n";
    foreach ($scan as $r) {
      $sizeKB = number_format($r['size']/1024,1).' KB';
      $av = $r['av'].($r['engine'] ? ' ('.$r['engine'].')' : '').(isset($r['code']) ? ' #'.$r['code'] : '');
      $text .= "{$r['name']} | {$sizeKB} | {$r['mime']} | {$av}\n";
    }
  }

  $sent = false;
  try {
    // Provided by your existing mail_common.php
    $sent = send_mail_smtp2go(HELP_DESK_TO, $email, $hdr, $html, $text, $attachments);
  } catch (Throwable $e) {
    error_log('Mailer exception: '.$e->getMessage());
  }

  // Final log
  write_json_file($LOG_DIR . '/' . $reqId . '.json', [
    'meta'  => $meta,
    'scan'  => $scan,
    'email' => ['ok'=>$sent],
    'doneAt'=> date('c'),
  ]);

} catch (Throwable $e) {
  // If the exception happened before we ACKed, return JSON error cleanly.
  if (!headers_sent()) {
    json_fail('Server error', 500);
  }
  // If we already ACKed, just log it.
  error_log('Unhandled exception after ACK: '.$e->getMessage());
}
