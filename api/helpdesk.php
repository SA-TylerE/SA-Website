<?php
// api/helpdesk.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Helpdesk form (Support). Immediately acknowledges receipt to client,
 * then scans attachments and sends email AFTER the HTTP response is flushed.
 */

/* ---------------- Config ---------------- */
const MAX_FILES           = 5;
const MAX_SIZE_BYTES      = 5 * 1024 * 1024; // 5 MB
const ALLOWED_EXT_REGEX   = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';
const ALLOWED_MIME        = [
  'image/png','image/jpeg','application/pdf','text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/csv'
];
/* ---------------------------------------- */

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

/** Try clamdscan/clamscan; return ['status'=>'clean'|'infected'|'error'|'unavailable','engine'=>?] */
function antivirus_scan_detail(string $path): array {
  $engine = null; $cmd = null;
  if (trim(shell_exec('command -v clamdscan 2>/dev/null') ?? '') !== '') {
    $engine = 'clamdscan';
    $cmd = 'clamdscan --no-summary '.escapeshellarg($path);
  } elseif (trim(shell_exec('command -v clamscan 2>/dev/null') ?? '') !== '') {
    $engine = 'clamscan';
    $cmd = 'clamscan --no-summary '.escapeshellarg($path);
  } else {
    return ['status'=>'unavailable','engine'=>null];
  }
  exec($cmd, $out, $code);
  if ($code === 0) return ['status'=>'clean','engine'=>$engine];
  if ($code === 1) return ['status'=>'infected','engine'=>$engine];
  return ['status'=>'error','engine'=>$engine];
}

/** Flush JSON response now, keep process alive to finish work. */
function respond_now_and_continue(array $payload = ['ok'=>true]): void {
  ignore_user_abort(true);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
  echo json_encode($payload, JSON_UNESCAPED_SLASHES);
  // Try FastCGI graceful finish (best)
  if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
    return;
  }
  // Fallback: close connection
  header('Connection: close');
  $size = ob_get_length();
  if ($size === false) { $size = 0; }
  header("Content-Length: ".$size);
  @ob_end_flush();
  @flush();
  @ob_flush();
}

/* ===== Parse + stage request ===== */

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$issue   = trim($data['issue']   ?? '');
$hp      = trim($data['website_honeypot'] ?? '');

if ($hp !== '') { respond_now_and_continue(['ok'=>true]); exit; }
if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');

$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

/* Stage uploads to a private temp job folder */
$jobDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.'sa_job_'.bin2hex(random_bytes(6));
if (!@mkdir($jobDir, 0700, false)) {
  json_fail('Server is busy. Please try again.');
}
$staged = []; // each: ['name','path','size','client_type']

if (!empty($_FILES['attachments'])) {
  $flat = normalize_files_array($_FILES['attachments']);
  // keep only non-empty
  $flat = array_values(array_filter($flat, fn($f)=> ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
  if (count($flat) > MAX_FILES) { json_fail('Too many files'); }

  foreach ($flat as $idx => $f) {
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
      // remove job dir on hard failure
      json_fail('Upload error on file '.$idx);
    }
    $nameBase = basename($f['name'] ?? 'file');
    if (!preg_match(ALLOWED_EXT_REGEX, $nameBase)) continue;                 // drop early
    $size = (int)($f['size'] ?? 0);
    if ($size > MAX_SIZE_BYTES) continue;                                    // drop early
    if (empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) continue;

    $safeName = preg_replace('/[^A-Za-z0-9._-]+/', '_', $nameBase);
    $dest = $jobDir.DIRECTORY_SEPARATOR.$safeName;
    if (!@move_uploaded_file($f['tmp_name'], $dest)) continue;
    // lock down perms
    @chmod($dest, 0600);

    $staged[] = [
      'name'        => $safeName,
      'path'        => $dest,
      'size'        => $size,
      'client_type' => (string)($f['type'] ?? ''),
    ];
  }
}

/* Immediately ACK to the browser */
respond_now_and_continue(['ok'=>true, 'message'=>'Accepted']);

/* ===== Continue working after response is flushed ===== */

set_time_limit(300); // allow time to scan+send
$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$htmlIssue = nl2br($safe($issue));

$ipRow = '<tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.$safe($ip).'</td></tr>';

$html = '
  <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
    <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
      <h2 style="margin:0 0 12px">Support Form</h2>
      <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
        <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.$safe($name).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.$safe($company).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.$safe($email).'" style="color:#aa1e2e">'.$safe($email).'</a></td></tr>
        '.$ipRow.'
      </table>
      <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
      <div>
        <div style="font-weight:700; margin:0 0 6px">Issue</div>
        <div style="white-space:pre-wrap; line-height:1.5">'.$htmlIssue.'</div>
      </div>
    </div>
  </div>';

$text = "Support Form\n"
      . "From: $name\n"
      . "Company: $company\n"
      . "Email: $email\n"
      . "IP: $ip\n\n"
      . "$issue\n";

/* Scan and prepare attachments */
$attachments = [];
$scanReport  = [];

foreach ($staged as $file) {
  $path = $file['path']; $name = $file['name']; $size=(int)$file['size'];
  $mime = detect_mime_safely($path, $name);

  $verdict = 'attached';
  $reason  = '';

  if ($size > MAX_SIZE_BYTES) { $verdict='blocked'; $reason='too large'; }
  if (!preg_match(ALLOWED_EXT_REGEX, $name)) { $verdict='blocked'; $reason='type not allowed'; }
  if ($verdict !== 'blocked' && !in_array($mime, ALLOWED_MIME, true)) { $verdict='blocked'; $reason='MIME check failed'; }

  $av = ['status'=>'unavailable','engine'=>null];
  if ($verdict !== 'blocked') {
    $av = antivirus_scan_detail($path);
    if ($av['status'] === 'infected') { $verdict='blocked'; $reason='virus detected'; }
    elseif ($av['status'] === 'error') { $reason = 'AV error (proceeded)'; }
  }

  $sha256 = function_exists('hash_file') ? hash_file('sha256', $path) : null;

  $scanReport[] = [
    'name'   => $name,
    'size'   => $size,
    'mime'   => $mime,
    'sha256' => $sha256,
    'engine' => $av['engine'],
    'av'     => $av['status'],
    'action' => ($verdict === 'blocked' ? 'blocked' : 'attached'),
    'note'   => $reason,
  ];

  if ($verdict !== 'blocked') {
    $attachments[] = ['path'=>$path, 'name'=>$name];
  }
}

/* Append scan report */
if (!empty($scanReport)) {
  $html .= '<div style="height:10px"></div>'
         . '<div style="padding:12px; border:1px solid #e6e6e6; border-radius:10px; background:#fafafa">'
         . '<div style="font-weight:800; margin:0 0 8px; color:#58595b">Attachment scan report</div>'
         . '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%; border-collapse:collapse; font-size:0.95rem">';
  $html .= '<tr style="background:#fff"><th align="left">File</th><th align="left">Size</th><th align="left">MIME</th><th align="left">AV</th><th align="left">Action</th></tr>';
  foreach ($scanReport as $r) {
    $sizeKB = number_format($r['size']/1024, 1).' KB';
    $avLabel = $r['av'].($r['engine'] ? ' ('.$r['engine'].')' : '').($r['note'] ? ' — '.$r['note'] : '');
    $sha = $r['sha256'] ? '<br><span style="color:#9aa0a6;font-size:0.85em">sha256: '.htmlspecialchars($r['sha256']).'</span>' : '';
    $html .= '<tr style="background:#fff"><td>'.htmlspecialchars($r['name']).$sha.'</td>'
          .  '<td>'.$sizeKB.'</td><td>'.htmlspecialchars($r['mime']).'</td>'
          .  '<td>'.htmlspecialchars($avLabel).'</td>'
          .  '<td>'.htmlspecialchars($r['action']).'</td></tr>';
  }
  $html .= '</table></div>';

  $text .= "\n--- Attachment scan report ---\n";
  foreach ($scanReport as $r) {
    $sizeKB = number_format($r['size']/1024, 1).' KB';
    $avLabel = $r['av'].($r['engine'] ? " ({$r['engine']})" : '').($r['note'] ? " — {$r['note']}" : '');
    $text .= "{$r['name']} | {$sizeKB} | {$r['mime']} | {$avLabel} | {$r['action']}";
    if (!empty($r['sha256'])) $text .= " | sha256: {$r['sha256']}";
    $text .= "\n";
  }
}

/* Send email (subject per your spec) */
$subject = "Support Form: New request";
try {
  send_mail_smtp2go(
    HELP_DESK_TO,   // helpdesk@systemalternatives.net (set in mail_common.php)
    $email,         // reply-to
    $subject,
    $html,
    $text,
    $attachments
  );
} catch (Throwable $e) {
  error_log("helpdesk mail send error: ".$e->getMessage());
}

/* Cleanup staged files */
foreach ($staged as $f) { @unlink($f['path']); }
@rmdir($jobDir);

exit; // finished work after response
