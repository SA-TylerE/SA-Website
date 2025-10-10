<?php
// api/helpdesk.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Helpdesk (Support) endpoint
 * - Accepts application/json or multipart/form-data (with attachments)
 * - Requires: name, email, issue  (company optional)
 * - Subject: "Support Form: <provided subject OR first 80 chars of issue>"
 * - Attachments: up to 5 files, 5MB each, allowlisted types; optional AV scan via ClamAV
 * - Appends a scan report to the email
 * - Uses "SA Website" as sender name (set in mail_common.php)
 */

// ===== Helpers =====

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

// MIME detection (works even if fileinfo is disabled)
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

// Antivirus wrapper: returns detail
// status: 'clean' | 'infected' | 'error' | 'unavailable'
function antivirus_scan_detail(string $path): array {
  // Absolute paths avoid PATH issues under www-data
  $clamdscan = '/usr/bin/clamdscan';
  $clamscan  = '/usr/bin/clamscan';

  // Build commands (no-summary keeps output short; --fdpass lets clamdscan read the file even if perms are tight)
  $candidates = [];
  if (is_executable($clamdscan)) {
    $candidates[] = [$clamdscan, "$clamdscan --no-summary --fdpass ".escapeshellarg($path), 'clamdscan'];
  }
  if (is_executable($clamscan)) {
    $candidates[] = [$clamscan,  "$clamscan --no-summary ".escapeshellarg($path),       'clamscan'];
  }
  if (!$candidates) {
    return ['status'=>'unavailable','engine'=>null,'code'=>2,'stdout'=>'','stderr'=>'no scanner binary'];
  }

  foreach ($candidates as [$bin,$cmd,$engine]) {
    // Capture stdout+stderr and exit code
    $descriptors = [
      1 => ['pipe','w'], // stdout
      2 => ['pipe','w'], // stderr
    ];
    $proc = proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($proc)) continue;

    stream_set_blocking($pipes[1], true);
    stream_set_blocking($pipes[2], true);
    $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $status = proc_get_status($proc);
    $code   = $status['exitcode'];
    proc_close($proc);

    // Normalize
    if ($code === 0) return ['status'=>'clean',    'engine'=>$engine, 'code'=>$code, 'stdout'=>$stdout, 'stderr'=>$stderr];
    if ($code === 1) return ['status'=>'infected', 'engine'=>$engine, 'code'=>$code, 'stdout'=>$stdout, 'stderr'=>$stderr];
    // code 2 or anything else = error
    // Try next engine (fallback from clamdscan -> clamscan). If this *is* the last, return error detail.
    if ($engine === 'clamscan' || count($candidates) === 1) {
      return ['status'=>'error', 'engine'=>$engine, 'code'=>$code, 'stdout'=>$stdout, 'stderr'=>$stderr];
    }
  }

  return ['status'=>'error','engine'=>null,'code'=>2,'stdout'=>'','stderr'=>'proc open failed'];
}

// ===== Validate request =====

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$issue   = trim($data['issue']   ?? '');
$postedSubject = trim($data['subject'] ?? ''); // client may send a derived subject
$hp      = trim($data['website_honeypot'] ?? ''); // spam trap

if ($hp !== '') { echo json_encode(['ok'=>true]); exit; } // quietly accept bots
if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');

$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

// Build subject (derive if missing)
$subjectRaw = $postedSubject !== '' ? $postedSubject : mb_substr(preg_replace('/\s+/', ' ', $issue), 0, 80);
$emailSubject = 'Support Form: ' . ($subjectRaw !== '' ? $subjectRaw : '(no subject)');
$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$htmlIssue = nl2br($safe($issue));
$htmlHeader = $safe($emailSubject);

// ===== Build HTML & text =====

$html = '
  <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
    <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
      <h2 style="margin:0 0 12px">'.$htmlHeader.'</h2>
      <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
        <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.$safe($name).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.$safe($company).'</td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.$safe($email).'" style="color:#aa1e2e">'.$safe($email).'</a></td></tr>
        <tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.$safe($ip).'</td></tr>
      </table>
      <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
      <div>
        <div style="font-weight:700; margin:0 0 6px">Issue</div>
        <div style="white-space:pre-wrap; line-height:1.5">'.$htmlIssue.'</div>
      </div>
    </div>
  </div>';

$text = $emailSubject."\n"
      . "From: $name\n"
      . "Company: $company\n"
      . "Email: $email\n"
      . "IP: $ip\n\n"
      . "$issue\n";

// ===== Attachments (validate + AV scan + report) =====

$attachments = [];
$scanReport  = [];

if (!empty($_FILES['attachments'])) {
  $MAX_FILES  = 5;
  $MAX_SIZE   = 5 * 1024 * 1024; // 5 MB
  $allowedExt = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';
  $allowedMime = [
    'image/png','image/jpeg','application/pdf','text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/csv'
  ];

  $flat = normalize_files_array($_FILES['attachments']);
  $nonEmpty = array_values(array_filter($flat, fn($f) => ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
  if (count($nonEmpty) > $MAX_FILES) json_fail("Too many files (max $MAX_FILES)");

  foreach ($flat as $idx => $f) {
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) continue;

    // upload checks
    if ($f['error'] !== UPLOAD_ERR_OK || empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) {
      json_fail('Upload error on file '.$idx);
    }

    $tmp  = $f['tmp_name'];
    $name = $f['name'] ?? 'file';
    $size = (int)($f['size'] ?? 0);

    $verdict = 'attached';
    $reason  = '';

    if ($size > $MAX_SIZE) { $verdict='blocked'; $reason='too large'; }
    if (!preg_match($allowedExt, $name)) { $verdict='blocked'; $reason='type not allowed'; }

    $mime = detect_mime_safely($tmp, $name);
    if ($verdict !== 'blocked' && !in_array($mime, $allowedMime, true)) { $verdict='blocked'; $reason='MIME check failed'; }

    $av = ['status'=>'unavailable','engine'=>null,'code'=>null,'stdout'=>'','stderr'=>''];

    if ($verdict !== 'blocked') {
      $av = antivirus_scan_detail($tmp);

      if ($av['status'] === 'infected') {
        $verdict = 'blocked';
        $reason  = 'virus detected';
      } elseif ($av['status'] === 'error') {
        // SAFER policy: block when AV is unavailable or errors out
        $verdict = 'blocked';
        $reason  = "AV error ({$av['engine']}) code={$av['code']}";
        error_log("AV ERROR: engine={$av['engine']} code={$av['code']} stdout=".
                  substr((string)$av['stdout'],0,500).
                  " stderr=".substr((string)$av['stderr'],0,500));
      }
    }

    $sha256 = function_exists('hash_file') ? hash_file('sha256', $tmp) : null;

    $scanReport[] = [
      'name'   => $name,
      'size'   => $size,
      'mime'   => $mime,
      'sha256' => $sha256,
      'engine' => $av['engine'],
      'av'     => $av['status'],
      'action' => ($verdict === 'blocked' ? 'blocked' : 'attached'),
      'note'   => $reason
    ];

    if ($verdict !== 'blocked') {
      $cleanName = preg_replace('/[^A-Za-z0-9._-]+/', '_', basename($name));
      $attachments[] = ['path'=>$tmp, 'name'=>$cleanName];
    }
  }
}

// Append scan report
if (!empty($scanReport)) {
  $html .= '<div style="height:10px"></div>'
        .  '<div style="padding:12px; border:1px solid #e6e6e6; border-radius:10px; background:#fafafa">'
        .  '<div style="font-weight:800; margin:0 0 8px; color:#58595b">Attachment scan report</div>'
        .  '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%; border-collapse:collapse; font-size:0.95rem">'
        .  '<tr style="background:#fff"><th align="left">File</th><th align="left">Size</th><th align="left">MIME</th><th align="left">AV</th><th align="left">Action</th></tr>';
  foreach ($scanReport as $r) {
    $sizeKB = number_format($r['size']/1024, 1).' KB';
    $avLabel = $r['av'];
    if ($r['engine']) $avLabel .= ' ('.$r['engine'].')';
    if ($r['note'])   $avLabel .= ' — '.$r['note'];
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

// Send
send_mail_smtp2go(
  HELP_DESK_TO,    // e.g., helpdesk@systemalternatives.net
  $email,          // reply-to
  $emailSubject,
  $html,
  $text,
  $attachments
);

echo json_encode(['ok'=>true,'message'=>'Sent to helpdesk'], JSON_UNESCAPED_SLASHES);
