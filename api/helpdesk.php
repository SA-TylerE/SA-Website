<?php
// api/helpdesk.php
declare(strict_types=1);
require_once __DIR__.'/mail_common.php';

/**
 * Helpdesk (Support) endpoint — early ACK + serialized clamdscan + queue cleanup
 * - Accepts JSON or multipart/form-data with attachments
 * - Early ACKs {"ok":true} so UI can show "Sent" immediately
 * - Stages files in api/queue/<req-id>/, scans with clamdscan ONLY (sequential),
 *   retries until scan completes (clean or infected), sends mail,
 *   then ALWAYS deletes the per-request folder
 * - Uses a global flock to ensure ONLY ONE request is scanning at a time
 * - Writes a structured JSONL log to api/logs/helpdesk.log
 *
 * Notes:
 * - We now get clamdscan's exit code from proc_close() (reliable), not proc_get_status()
 * - Logging is throttled to avoid log bloat; retry warnings at most every 5 minutes
 * - Remove deprecated "AllowSupplementaryGroups" from clamd.conf to keep stderr clean
 */

// ---------- Paths / Limits ----------
const QUEUE_ROOT       = __DIR__ . '/queue';
const LOG_DIR          = __DIR__ . '/logs';
const LOG_FILE         = LOG_DIR . '/helpdesk.log';
const SCAN_LOCK_FILE   = __DIR__ . '/clamav.scan.lock';  // global mutex
const MAX_FILES        = 5;
const MAX_SIZE_BYTES   = 5 * 1024 * 1024; // 5 MB
const CLAMDSCAN_BIN    = '/usr/bin/clamdscan';
const CLAMD_CONF       = '/etc/clamav/clamd.conf';       // ensure this matches your host

// ---------- Helpers ----------
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

function detect_mime_safely(string $path, string $name): string {
  if (class_exists('finfo')) {
    $fi = new finfo(FILEINFO_MIME_TYPE);
    $m  = $fi->file($path);
    if (is_string($m) && $m !== '') return $m;
  }
  if (function_exists('mime_content_type')) {
    $m = mime_content_type($path);
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

function normalize_files_array(array $files): array {
  $out = [];
  if (is_array($files['name'] ?? null)) {
    foreach ($files['name'] as $i => $name) {
      $out[] = [
        'name'     => $files['name'][$i]     ?? '',
        'type'     => $files['type'][$i]     ?? '',
        'tmp_name' => $files['tmp_name'][$i] ?? '',
        'error'    => $files['error'][$i]    ?? UPLOAD_ERR_NO_FILE,
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

function rrmdir(string $dir): void {
  if (!is_dir($dir)) return;
  $items = scandir($dir); if ($items === false) return;
  foreach ($items as $it) {
    if ($it === '.' || $it === '..') continue;
    $p = $dir.DIRECTORY_SEPARATOR.$it;
    if (is_dir($p)) rrmdir($p); else @unlink($p);
  }
  @rmdir($dir);
}

function ensure_dirs(): void {
  if (!is_dir(QUEUE_ROOT)) @mkdir(QUEUE_ROOT, 0770, true);
  if (!is_dir(LOG_DIR))    @mkdir(LOG_DIR,   0750, true);
  if (!file_exists(LOG_FILE)) @touch(LOG_FILE);
  @chmod(LOG_FILE, 0640);
}

function req_id(): string {
  return date('Ymd-His').'-'.bin2hex(random_bytes(4));
}

function log_json(string $level, string $reqId, string $msg, array $ctx = []): void {
  $line = json_encode([
    'ts'     => gmdate('c'),
    'level'  => $level,
    'req_id' => $reqId,
    'message'=> $msg,
    'ctx'    => $ctx,
  ], JSON_UNESCAPED_SLASHES);
  if ($line !== false) {
    @file_put_contents(LOG_FILE, $line."\n", FILE_APPEND);
  }
}

function make_work_dir(string $reqId): string {
  $dir = QUEUE_ROOT.'/'.$reqId;
  if (!@mkdir($dir, 0770, true)) json_fail('Server storage unavailable', 500);
  return realpath($dir) ?: $dir;
}

function early_ack_then_continue(array $payload=['ok'=>true]): void {
  echo json_encode($payload, JSON_UNESCAPED_SLASHES), "\n";
  if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
  } else {
    @ob_end_flush(); @flush();
  }
}

// ---------- ClamAV diagnostics helpers ----------
function clamd_conf_socket(string $confPath = CLAMD_CONF): ?string {
  if (!is_readable($confPath)) return null;
  $sock = null;
  foreach (file($confPath, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    if ($line === '' || $line[0] === '#') continue;
    if (preg_match('/^\s*LocalSocket\s+(.*)\s*$/i', $line, $m)) {
      $sock = trim($m[1]);
      break;
    }
  }
  return $sock ?: null;
}

function clamd_ping(?string $sockPath, string $reqId, string $when): array {
  $sockPath = $sockPath ?: clamd_conf_socket();
  if (!$sockPath) {
    log_json('error', $reqId, "clamd PING: no LocalSocket found", ['when'=>$when, 'conf'=>CLAMD_CONF]);
    return ['ok'=>false, 'err'=>'no socket path'];
  }
  $errno = 0; $errstr = '';
  $fp = @stream_socket_client("unix://".$sockPath, $errno, $errstr, 2.0, STREAM_CLIENT_CONNECT);
  if (!$fp) {
    log_json('error', $reqId, "clamd PING connect failed", [
      'when'=>$when, 'socket'=>$sockPath, 'errno'=>$errno, 'error'=>$errstr
    ]);
    return ['ok'=>false, 'errno'=>$errno, 'err'=>$errstr];
  }
  stream_set_timeout($fp, 2);
  fwrite($fp, "PING\n");
  $resp = fgets($fp, 16) ?: '';
  fclose($fp);
  $ok = (trim($resp) === 'PONG');
  log_json($ok ? 'info' : 'warn', $reqId, "clamd PING ".($ok?'OK':'bad'), [
    'when'=>$when, 'socket'=>$sockPath, 'resp'=>trim($resp)
  ]);
  return ['ok'=>$ok, 'resp'=>trim($resp)];
}

/**
 * Force clamdscan only (with explicit config).
 * Returns: ['status'=>'clean'|'infected'|'error'|'unavailable','engine'=>'clamdscan','code'=>int,'stdout'=>string,'stderr'=>string]
 */
function antivirus_scan_once(string $path, string $reqId, string $filename): array {
  if (!is_executable(CLAMDSCAN_BIN)) {
    log_json('error', $reqId, 'clamdscan not executable', ['bin'=>CLAMDSCAN_BIN]);
    return ['status'=>'error','engine'=>'clamdscan','code'=>127,'stdout'=>'','stderr'=>'clamdscan not found or not executable'];
  }

  $cmdParts = [
    escapeshellcmd(CLAMDSCAN_BIN),
    '--no-summary',
    '--fdpass',
    '--config-file='.escapeshellarg(CLAMD_CONF),
    escapeshellarg($path)
  ];
  $cmd = implode(' ', $cmdParts);

  $desc = [1=>['pipe','w'], 2=>['pipe','w']];
  $proc = @proc_open($cmd, $desc, $pipes);
  if (!is_resource($proc)) {
    log_json('error', $reqId, 'proc_open failed for clamdscan', ['file'=>$filename]);
    clamd_ping(clamd_conf_socket(), $reqId, 'proc_open_failed');
    return ['status'=>'error','engine'=>'clamdscan','code'=>2,'stdout'=>'','stderr'=>'proc_open failed'];
  }

  stream_set_blocking($pipes[1], true);
  stream_set_blocking($pipes[2], true);
  $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
  $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);

  // IMPORTANT: proc_close() returns the *real* exit code. proc_get_status()['exitcode'] may be -1.
  $code = proc_close($proc);

  // Only log on non-clean outcomes to reduce noise
  if ($code !== 0) {
    log_json('warn', $reqId, 'clamdscan nonzero exit', [
      'file'=>$filename, 'exit_code'=>$code,
      'stdout'=>substr((string)$stdout,0,300),
      'stderr'=>substr((string)$stderr,0,300),
      'cmd'=>$cmd
    ]);
  }

  if ($code === 0) return ['status'=>'clean',    'engine'=>'clamdscan','code'=>$code,'stdout'=>$stdout,'stderr'=>$stderr];
  if ($code === 1) return ['status'=>'infected', 'engine'=>'clamdscan','code'=>$code,'stdout'=>$stdout,'stderr'=>$stderr];

  // Exit 2 or other errors — do a socket PING to capture errno/message
  clamd_ping(clamd_conf_socket(), $reqId, 'exit_code_'.$code);

  // Classify common messages as "unavailable" to separate from generic error
  $err = strtolower($stdout."\n".$stderr);
  if (strpos($err, 'connect') !== false || strpos($err, 'socket') !== false) {
    return ['status'=>'unavailable','engine'=>'clamdscan','code'=>$code,'stdout'=>$stdout,'stderr'=>$stderr];
  }
  return ['status'=>'error','engine'=>'clamdscan','code'=>$code,'stdout'=>$stdout,'stderr'=>$stderr];
}

/**
 * Retry until scan finishes (clean or infected). Never “skip”.
 * Logs periodic warnings when clamd is unavailable/error (max once/5 min).
 */
function antivirus_scan_with_retry(string $path, string $reqId, string $filename): array {
  $attempt = 0;
  $lastWarnAt = 0;
  while (true) {
    $attempt++;
    $res = antivirus_scan_once($path, $reqId, $filename);

    if ($res['status'] === 'clean' || $res['status'] === 'infected') {
      if ($attempt > 1) {
        log_json('info', $reqId, 'AV scan completed after retries', [
          'file'=>$filename, 'attempts'=>$attempt, 'final_status'=>$res['status']
        ]);
      }
      return $res;
    }

    // unavailable/error: wait and retry, never skip
    $now = time();
    if ($now - $lastWarnAt >= 300) { // at most once every 5 minutes
      log_json('warn', $reqId, 'AV scan retry (daemon unavailable or error)', [
        'file'=>$filename, 'attempt'=>$attempt, 'status'=>$res['status'],
        'note'=>'throttled warning (5m)'
      ]);
      $lastWarnAt = $now;
    }
    sleep(2); // gentle backoff; keep CPU low while waiting for clamd
  }
}

/**
 * Acquire a global scan lock so only one request scans at a time.
 * Returns the lock handle which must be kept open until release.
 */
function acquire_scan_lock() {
  $fh = fopen(SCAN_LOCK_FILE, 'c');
  if ($fh === false) {
    // As a fallback, proceed without lock but log error
    return null;
  }
  // Make sure perms are sane
  @chmod(SCAN_LOCK_FILE, 0660);
  // Block until we get the lock to serialize scanning
  if (!flock($fh, LOCK_EX)) {
    // If lock fails (rare), still proceed but log
    log_json('error', 'n/a', 'Failed to acquire scan lock');
    return null;
  }
  return $fh;
}

function release_scan_lock($fh): void {
  if (is_resource($fh)) {
    @flock($fh, LOCK_UN);
    @fclose($fh);
  }
}

// ---------- Begin request ----------
ensure_dirs();
$reqId  = req_id();

$data    = get_request_data();
$name    = trim($data['name']    ?? '');
$company = trim($data['company'] ?? '');
$email   = trim($data['email']   ?? '');
$issue   = trim($data['issue']   ?? '');
$postedSubject = trim($data['subject'] ?? '');
$hp      = trim($data['website_honeypot'] ?? '');
$ip      = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'n/a';

if ($hp !== '') { echo json_encode(['ok'=>true]); exit; }
if ($name === '' || $email === '' || $issue === '') json_fail('Missing required fields');

$subjectRaw   = $postedSubject !== '' ? $postedSubject : mb_substr(preg_replace('/\s+/', ' ', $issue), 0, 80);
$emailSubject = 'Support Form: ' . ($subjectRaw !== '' ? $subjectRaw : '(no subject)');
$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$htmlIssue  = nl2br($safe($issue));
$htmlHeader = $safe($emailSubject);

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
      <div><div style="font-weight:700; margin:0 0 6px">Issue</div><div style="white-space:pre-wrap; line-height:1.5">'.$htmlIssue.'</div></div>
    </div>
  </div>';

$text = $emailSubject."\n"
      . "From: $name\n"
      . "Company: $company\n"
      . "Email: $email\n"
      . "IP: $ip\n\n"
      . "$issue\n";

// Early ACK so the UI shows "Sent" immediately
early_ack_then_continue(['ok'=>true,'message'=>'Received']);

// Background work continues
ignore_user_abort(true);

$attachments = [];
$scanReport  = [];
$workDir     = null;
$lockHandle  = null;

try {
  // Handle attachments if any
  if (!empty($_FILES['attachments'])) {
    $flat = normalize_files_array($_FILES['attachments']);
    $nonEmpty = array_values(array_filter($flat, fn($f) => ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));

    if ($nonEmpty) $workDir = make_work_dir($reqId);

    $allowedExt  = '/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i';
    $allowedMime = [
      'image/png','image/jpeg','application/pdf','text/plain',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/csv'
    ];

    // Acquire global scan lock to serialize scanning across requests
    $lockHandle = acquire_scan_lock();
    if (!$lockHandle) {
      log_json('warn', $reqId, 'Proceeding without scan lock (acquire failed)');
    }

    $kept = 0;
    foreach ($flat as $idx => $f) {
      if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) continue;
      if ($kept >= MAX_FILES) { continue; }

      if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) {
        log_json('warn', $reqId, 'Upload error on file index', ['index'=>$idx]);
        continue;
      }

      $tmp  = $f['tmp_name'];
      $name = $f['name'] ?? 'file';
      $size = (int)($f['size'] ?? 0);

      // static checks first
      $verdict = 'candidate';
      $reason  = '';

      if ($size > MAX_SIZE_BYTES) { $verdict='blocked'; $reason='too large'; }
      if (!preg_match($allowedExt, $name)) { $verdict='blocked'; $reason='type not allowed'; }

      $cleanName = preg_replace('/[^A-Za-z0-9._-]+/', '_', basename($name));
      $destPath  = $workDir ? ($workDir . '/' . $cleanName) : $tmp;

      if ($workDir) {
        if (!@move_uploaded_file($tmp, $destPath)) {
          $destPath = $tmp; // fallback
        }
      }

      $mime = detect_mime_safely($destPath, $cleanName);
      if ($verdict !== 'blocked' && !in_array($mime, $allowedMime, true)) {
        $verdict='blocked'; $reason='MIME check failed';
      }

      // MUST scan every candidate sequentially.
      $av = ['status'=>null,'engine'=>'clamdscan','code'=>null,'stdout'=>'','stderr'=>''];
      if ($verdict !== 'blocked') {
        $av = antivirus_scan_with_retry($destPath, $reqId, $cleanName); // blocks until clean or infected
        if ($av['status'] === 'infected') {
          $verdict = 'blocked'; $reason = 'virus detected';
        } elseif ($av['status'] === 'clean') {
          $verdict = 'attached';
        } else {
          // Should not happen, but guard:
          $verdict = 'blocked'; $reason = 'scan anomaly';
          log_json('error', $reqId, 'Unexpected AV status', ['file'=>$cleanName, 'status'=>$av['status']]);
        }
      }

      $sha256 = function_exists('hash_file') && is_readable($destPath) ? hash_file('sha256', $destPath) : null;

      $scanReport[] = [
        'name'   => $cleanName,
        'size'   => $size,
        'mime'   => $mime,   // kept for internal checks/logging; not displayed
        'sha256' => $sha256,
        'engine' => $av['engine'] ?? 'clamdscan',
        'av'     => $av['status'] ?? 'n/a',
        'action' => ($verdict === 'blocked' ? 'blocked' : 'attached'),
        'note'   => $reason
      ];

      if ($verdict === 'attached') {
        $attachments[] = ['path'=>$destPath, 'name'=>$cleanName];
        $kept++;
      }
    }
  }

  // Append scan report to email
  if ($scanReport) {
    $html .= '<div style="height:10px"></div>'
          .  '<div style="padding:12px; border:1px solid #e6e6e6; border-radius:10px; background:#fafafa">'
          .  '<div style="font-weight:800; margin:0 0 8px; color:#58595b">Attachment scan report</div>'
          .  '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%; border-collapse:collapse; font-size:0.95rem">'
          // Removed MIME column
          .  '<tr style="background:#fff"><th align="left">File</th><th align="left">Size</th><th align="left">AV</th><th align="left">Action</th></tr>';
    // HTML table rows
    foreach ($scanReport as $r) {
      $sizeKB  = number_format($r['size']/1024, 1).' KB';

      // status + note only
      $avLabel = $r['av'];
      if (!empty($r['note'])) $avLabel .= ' ' . $r['note'];

      // VirusTotal link (unchanged)
      $sha = '';
      if (!empty($r['sha256'])) {
        $hash = $r['sha256'];
        $vt   = 'https://www.virustotal.com/gui/file/' . rawurlencode($hash);
        $sha  = '<br><span style="color:#9aa0a6;font-size:0.85em">'
              . '<a href="'.$vt.'" target="_blank" rel="noopener noreferrer"'
              . ' title="Open VirusTotal for this file (SHA-256)">VirusTotal scan</a>'
              . '</span>';
      }

      $html .= '<tr style="background:#fff"><td>'.htmlspecialchars($r['name']).$sha.'</td>'
            .  '<td>'.$sizeKB.'</td>'
            .  '<td>'.htmlspecialchars($avLabel).'</td>'
            .  '<td>'.htmlspecialchars($r['action']).'</td></tr>';
    }
    $html .= '</table></div>';

    // Plaintext lines
    $text .= "\n--- Attachment scan report ---\n";
    foreach ($scanReport as $r) {
      $sizeKB  = number_format($r['size']/1024, 1).' KB';

      // status only
      $avLabel = $r['av'];

      $text .= "{$r['name']} | {$sizeKB} | {$avLabel} | {$r['action']}";
      if (!empty($r['sha256'])) {
        $hash = $r['sha256'];
        $text .= " | VirusTotal: https://www.virustotal.com/gui/file/{$hash}";
      }
      $text .= "\n";
    }
  }

  // Send email (post-ACK)
  try {
    send_mail_smtp2go(
      HELP_DESK_TO,
      $email,
      $emailSubject,
      $html,
      $text,
      $attachments
    );
    $attachedCnt = count($attachments);
    $blockedCnt  = count(array_filter($scanReport, fn($r)=>$r['action']==='blocked'));
    log_json('info', $reqId, 'Mail sent', [
      'ip'=>$ip, 'subject'=>$emailSubject, 'from_email'=>$email, 'name'=>$name,
      'attachments_total'=>$attachedCnt, 'blocked_total'=>$blockedCnt
    ]);
  } catch (Throwable $e) {
    log_json('error', $reqId, 'Mail send error', ['error'=>$e->getMessage()]);
  }
} finally {
  // Release global lock (if held) and clean queue
  if ($lockHandle) release_scan_lock($lockHandle);
  if ($workDir && is_dir($workDir)) rrmdir($workDir);
}

// Done
exit;
