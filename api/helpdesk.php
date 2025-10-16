<?php
// api/helpdesk.php
declare(strict_types=1);

// Uses send_mail_smtp2go() from mail_common.php
require_once __DIR__ . '/mail_common.php';

ini_set('display_errors', '0');
error_reporting(E_ALL ^ E_NOTICE);
header('Content-Type: application/json; charset=utf-8');

// ---------- Small local helpers (no edit needed) ----------
function ensure_dir(string $path): void {
  if (!is_dir($path)) @mkdir($path, 0775, true);
}
function write_json(string $path, array $obj): void {
  ensure_dir(dirname($path));
  @file_put_contents($path, json_encode($obj, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function json_fail(string $msg, int $code = 400): void {
  http_response_code($code);
  echo json_encode(['ok'=>false,'error'=>$msg], JSON_UNESCAPED_SLASHES);
  exit;
}
// Normalize $_FILES entry (single/multi safe)
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
// conservative MIME detection
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
    'xlsx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'csv'=>'text/csv'
  ];
  return $map[$ext] ?? 'application/octet-stream';
}
// ClamAV scan (clamdscan preferred, clamscan fallback)
function antivirus_scan_detail(string $path): array {
  $cands = [];
  foreach (['/usr/bin/clamdscan' => '--no-summary --fdpass', '/usr/bin/clamscan' => '--no-summary'] as $bin=>$opts) {
    if (is_executable($bin)) $cands[] = [$bin, $opts, basename($bin)];
  }
  if (!$cands) return ['status'=>'unavailable','engine'=>null,'code'=>2,'stdout'=>'','stderr'=>'no scanner'];
  foreach ($cands as [$bin,$opts,$engine]) {
    $cmd = $bin.' '.$opts.' '.escapeshellarg($path).' 2>&1';
    $out = [];
    $rc  = 0;
    @exec($cmd, $out, $rc);
    $stdout = implode("\n", $out);
    if ($rc === 0) return ['status'=>'clean',    'engine'=>$engine,'code'=>$rc,'stdout'=>$stdout,'stderr'=>''];
    if ($rc === 1) return ['status'=>'infected', 'engine'=>$engine,'code'=>$rc,'stdout'=>$stdout,'stderr'=>''];
    // try next engine
    $last = end($cands);
    if ($bin === $last[0]) return ['status'=>'error','engine'=>$engine,'code'=>$rc,'stdout'=>$stdout,'stderr'=>'rc!=0'];
  }
  return ['status'=>'error','engine'=>null,'code'=>2,'stdout'=>'','stderr'=>'scan failed'];
}
// ---------------------------------------------------------

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok'=>false,'error'=>'Method not allowed']);
  exit;
}

// Honeypot (quiet accept)
if (trim((string)($_POST['website_honeypot'] ?? '')) !== '') {
  echo json_encode(['ok'=>true]);
  exit;
}

// Required fields
$name    = trim((string)($_POST['name'] ?? ''));
$company = trim((string)($_POST['company'] ?? ''));
$email   = trim((string)($_POST['email'] ?? ''));
$issue   = trim((string)($_POST['issue'] ?? ''));

if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) json_fail('Invalid email');

// Per-request workspace (make files durable before ACK)
$reqId    = date('Ymd_His').'_'.bin2hex(random_bytes(3));
$queueDir = __DIR__ . '/queue/' . $reqId;
$filesDir = $queueDir . '/files';
$logDir   = __DIR__ . '/logs/helpdesk/' . date('Y-m-d');
ensure_dir($filesDir);
ensure_dir($logDir);

// Intake metadata
$meta = [
  'id'      => $reqId,
  'time'    => date('c'),
  'ip'      => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '',
  'ua'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
  'fields'  => ['name'=>$name,'company'=>$company,'email'=>$email],
  'files'   => [],
];

// Accept up to N files and move them into $filesDir
$MAX_FILES   = 5;
$MAX_SIZE    = 5 * 1024 * 1024; // 5MB
$ALLOWED_EXT = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';
$ALLOWED_MIME = [
  'image/png','image/jpeg','application/pdf','text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','text/csv'
];

$storedFiles = [];
if (!empty($_FILES['attachments'])) {
  $flat = normalize_files_array($_FILES['attachments']);
  $nonEmpty = array_values(array_filter($flat, fn($f)=> (int)($f['error']??UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
  if (count($nonEmpty) > $MAX_FILES) json_fail("Too many files (max $MAX_FILES)");

  $idx = 0;
  foreach ($flat as $f) {
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) continue;
    if ($f['error'] !== UPLOAD_ERR_OK || empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) {
      $meta['files'][] = ['name'=>$f['name'] ?? 'file','status'=>'upload_error','code'=>$f['error']];
      continue;
    }
    $name = $f['name'] ?? 'file';
    $size = (int)($f['size'] ?? 0);
    if ($size > $MAX_SIZE) {
      $meta['files'][] = ['name'=>$name,'status'=>'too_large','size'=>$size];
      continue;
    }
    if (!preg_match($ALLOWED_EXT, $name)) {
      $meta['files'][] = ['name'=>$name,'status'=>'bad_type'];
      continue;
    }
    $mime = detect_mime_safely($f['tmp_name'], $name);
    if (!in_array($mime, $ALLOWED_MIME, true)) {
      $meta['files'][] = ['name'=>$name,'status'=>'mime_reject','mime'=>$mime];
      continue;
    }
    $clean = preg_replace('/[^A-Za-z0-9._-]+/', '_', basename($name));
    $dest  = $filesDir . '/' . sprintf('%02d_', $idx++) . $clean;
    if (@move_uploaded_file($f['tmp_name'], $dest)) {
      $storedFiles[] = ['name'=>$name,'path'=>$dest,'size'=>$size,'mime'=>$mime];
      $meta['files'][] = ['name'=>$name,'status'=>'received','stored'=>$dest,'size'=>$size,'mime'=>$mime];
    } else {
      $meta['files'][] = ['name'=>$name,'status'=>'move_failed'];
    }
  }
}

// Write an intake snapshot (optional, useful if something dies later)
write_json($queueDir.'/intake.json', [
  'meta'   => $meta,
  'fields' => ['name'=>$name,'company'=>$company,'email'=>$email,'issue_len'=>strlen($issue)],
]);

// ---------- FAST ACK to the browser ----------
$ack = ['ok'=>true,'id'=>$reqId];
echo json_encode($ack, JSON_UNESCAPED_SLASHES);

// Close the HTTP connection cleanly, then keep working
if (function_exists('fastcgi_finish_request')) {
  fastcgi_finish_request();
} else {
  ignore_user_abort(true);
  header('Connection: close');
  header('Content-Length: '.ob_get_length());
  @ob_end_flush(); @flush();
}

// ---------- Background work: scan, email, log ----------
$scanFindings = [];
$attachments  = [];
foreach ($storedFiles as $f) {
  $scan = antivirus_scan_detail($f['path']);
  $scanFindings[] = [
    'name' => $f['name'],
    'size' => $f['size'],
    'mime' => $f['mime'],
    'av'   => $scan['status'],
    'engine' => $scan['engine'],
    'code'   => $scan['code'],
  ];
  if ($scan['status'] === 'clean') {
    $attachments[] = ['path'=>$f['path'], 'name'=>basename($f['path'])];
  } else {
    // Block infected or AV error/unavailable
    if ($scan['status'] !== 'clean') {
      error_log("Helpdesk AV blocked file: {$f['name']} status={$scan['status']} engine={$scan['engine']} code={$scan['code']}");
    }
  }
}

// Build email pieces
$ip  = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
$hdr = 'Support Form: ' . (mb_substr(preg_replace('/\s+/', ' ', $issue), 0, 80) ?: '(no subject)');

$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$html = '
  <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#231f20">
    <div style="padding:16px 18px;border:1px solid #e6e6e6;border-radius:12px">
      <h2 style="margin:0 0 12px">'. $safe($hdr) .'</h2>
      <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%;border-collapse:collapse;margin:0 0 12px">
        <tr><td style="padding:6px 0;font-weight:700;width:120px">From</td><td style="padding:6px 0">'. $safe($name) .'</td></tr>
        <tr><td style="padding:6px 0;font-weight:700">Company</td><td style="padding:6px 0">'. $safe($company) .'</td></tr>
        <tr><td style="padding:6px 0;font-weight:700">Email</td><td style="padding:6px 0"><a href="mailto:'. $safe($email) .'" style="color:#aa1e2e">'. $safe($email) .'</a></td></tr>
        <tr><td style="padding:6px 0;font-weight:700">IP</td><td style="padding:6px 0">'. $safe($ip) .'</td></tr>
        <tr><td style="padding:6px 0;font-weight:700">Request ID</td><td style="padding:6px 0">'. $safe($reqId) .'</td></tr>
      </table>
      <div style="border-top:1px solid #e6e6e6;margin:10px 0 12px"></div>
      <div><div style="font-weight:700;margin:0 0 6px">Issue</div>
           <div style="white-space:pre-wrap;line-height:1.5">'. nl2br($safe($issue)) .'</div></div>
    </div>
  </div>';

$text = $hdr."\n"
      . "From: $name\nCompany: $company\nEmail: $email\nIP: $ip\nRequest ID: $reqId\n\n$issue\n";

// Append scan table if any files
if ($scanFindings) {
  $html .= '<div style="height:10px"></div>'
         . '<div style="padding:12px;border:1px solid #e6e6e6;border-radius:10px;background:#fafafa">'
         . '<div style="font-weight:800;margin:0 0 8px;color:#58595b">Attachment scan report</div>'
         . '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:0.95rem">'
         . '<tr style="background:#fff"><th align="left">File</th><th align="left">Size</th><th align="left">MIME</th><th align="left">AV</th></tr>';
  foreach ($scanFindings as $r) {
    $sizeKB = number_format($r['size']/1024,1).' KB';
    $av = $r['av'].($r['engine'] ? ' ('.$r['engine'].')':'').(isset($r['code'])?' #'.$r['code']:'');
    $html .= '<tr style="background:#fff">'
           . '<td>'.htmlspecialchars($r['name']).'</td>'
           . '<td>'.$sizeKB.'</td>'
           . '<td>'.htmlspecialchars((string)$r['mime']).'</td>'
           . '<td>'.htmlspecialchars($av).'</td>'
           . '</tr>';
  }
  $html .= '</table></div>';

  $text .= "\n--- Attachment scan report ---\n";
  foreach ($scanFindings as $r) {
    $sizeKB = number_format($r['size']/1024,1).' KB';
    $av = $r['av'].($r['engine'] ? ' ('.$r['engine'].')':'').(isset($r['code'])?' #'.$r['code']:'');
    $text .= "{$r['name']} | {$sizeKB} | {$r['mime']} | {$av}\n";
  }
}

// Send via SMTP2GO (from your existing mail_common.php)
$sendOk = false;
try {
  $sendOk = send_mail_smtp2go(
    HELP_DESK_TO,        // destination (from your config)
    $email,              // reply-to = user
    $hdr,                // subject
    $html,
    $text,
    $attachments         // [['path'=>..., 'name'=>...], ...]
  );
} catch (\Throwable $e) {
  error_log("Helpdesk mailer exception: ".$e->getMessage());
}

// Log outcome
$log = [
  'meta'   => $meta,
  'scan'   => $scanFindings,
  'email'  => ['ok'=>$sendOk],
  'doneAt' => date('c'),
];
write_json($logDir.'/'.$reqId.'.json', $log);

// (Optional) You can cron-clean queue/* older than N days.
