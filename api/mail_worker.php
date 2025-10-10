<?php
// api/mail_worker.php
declare(strict_types=1);

require_once __DIR__.'/mail_common.php';

/**
 * CLI worker: processes a single queued job (argv[1] path to .json)
 * - For 'contact': compose & send (no attachments)
 * - For 'helpdesk': AV-scan attachments, compose scan report, send; then delete staged files
 * - Logs to api/logs/app.log
 */

const LOG_DIR  = __DIR__ . '/logs';
const LOG_FILE = LOG_DIR . '/app.log';

function ensure_dir(string $d): void {
  if (!is_dir($d)) @mkdir($d, 0700, true);
  if (is_dir($d)) @chmod($d, 0700);
}

function wlog(string $msg): void {
  try {
    ensure_dir(LOG_DIR);
    $line = '['.date('Y-m-d H:i:s').'] worker: '.$msg.PHP_EOL;
    @file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
  } catch (\Throwable $e) { /* ignore */ }
}

function detect_mime_safely(string $path, string $name): string {
  if (class_exists('finfo')) {
    $fi = new finfo(FILEINFO_MIME_TYPE);
    $m  = @$fi->file($path);
    if (is_string($m) && $m !== '') return $m;
  }
  if (function_exists('mime_content_type')) {
    $m = @mime_content_type($path);
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

/** clamdscan/clamscan — returns ['status'=>clean|infected|error|unavailable,'engine'=>?] */
function antivirus_scan_detail(string $path): array {
  $candidates = [
    ['/usr/bin/clamdscan', 'clamdscan --no-summary --fdpass %s', 'clamdscan'],
    ['/usr/bin/clamscan',  'clamscan --no-summary %s',          'clamscan'],
  ];
  foreach ($candidates as [$bin, $fmt, $engine]) {
    if (!is_executable($bin)) continue;
    $cmd = sprintf($fmt, escapeshellarg($path));
    $out = [];
    $rc = 0;
    @exec($cmd, $out, $rc);
    if ($rc === 0) return ['status'=>'clean','engine'=>$engine];
    if ($rc === 1) return ['status'=>'infected','engine'=>$engine];
    return ['status'=>'error','engine'=>$engine];
  }
  return ['status'=>'unavailable','engine'=>null];
}

function safe(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function read_job(string $path): ?array {
  if (!is_file($path)) { wlog("job not found: $path"); return null; }
  $raw = @file_get_contents($path);
  if ($raw === false) { wlog("read failed: $path"); return null; }
  $j = json_decode($raw, true);
  if (!is_array($j)) { wlog("bad json: $path"); return null; }
  return $j;
}

function cleanup(array $job, string $path): void {
  if (!empty($job['attachments']) && is_array($job['attachments'])) {
    foreach ($job['attachments'] as $a) {
      if (!empty($a['path'])) @unlink($a['path']);
    }
  }
  @unlink($path);
}

function send_contact(array $job): void {
  $name    = (string)($job['name']    ?? '');
  $company = (string)($job['company'] ?? '');
  $email   = (string)($job['email']   ?? '');
  $phone   = (string)($job['phone']   ?? '');
  $subject = (string)($job['subject'] ?? '');
  $message = (string)($job['message'] ?? '');
  $ip      = (string)($job['ip']      ?? 'n/a');

  $emailSubject = 'Contact Form: ' . $subject;
  $html = '
    <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
      <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
        <h2 style="margin:0 0 12px">'.safe($emailSubject).'</h2>
        <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
          <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.safe($name).'</td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.safe($company).'</td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.safe($email).'" style="color:#aa1e2e">'.safe($email).'</a></td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">Phone</td><td style="padding:6px 0;">'.($phone!==''?safe($phone):'<span style="color:#9aa0a6">n/a</span>').'</td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.safe($ip).'</td></tr>
        </table>
        <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
        <div><div style="font-weight:700; margin:0 0 6px">Message</div>
             <div style="white-space:pre-wrap; line-height:1.5">'.nl2br(safe($message)).'</div></div>
      </div>
    </div>';
  $text = $emailSubject."\n"
        . "From: $name\nCompany: $company\nEmail: $email\nPhone: ".($phone!==''?$phone:'n/a')."\nIP: $ip\n\n$message\n";

  send_mail_smtp2go(
    CONTACT_TO,     // defined in mail_common.php
    $email,         // reply-to
    $emailSubject,
    $html,
    $text
  );
}

function send_helpdesk(array $job): void {
  $name    = (string)($job['name']    ?? '');
  $company = (string)($job['company'] ?? '');
  $email   = (string)($job['email']   ?? '');
  $issue   = (string)($job['issue']   ?? '');
  $ip      = (string)($job['ip']      ?? 'n/a');

  $subject = 'Support Form: ' . (mb_substr(preg_replace('/\s+/', ' ', $issue), 0, 80) ?: '(no subject)');
  $html = '
    <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
      <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
        <h2 style="margin:0 0 12px">'.safe($subject).'</h2>
        <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
          <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.safe($name).'</td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.safe($company).'</td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.safe($email).'" style="color:#aa1e2e">'.safe($email).'</a></td></tr>
          <tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.safe($ip).'</td></tr>
        </table>
        <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
        <div><div style="font-weight:700; margin:0 0 6px">Issue</div>
             <div style="white-space:pre-wrap; line-height:1.5">'.nl2br(safe($issue)).'</div></div>
      </div>
    </div>';

  $text = $subject."\nFrom: $name\nCompany: $company\nEmail: $email\nIP: $ip\n\n$issue\n";

  // Validate & optionally AV-scan attachments already staged in queue/
  $attachments = [];
  $scanReport  = [];

  if (!empty($job['attachments']) && is_array($job['attachments'])) {
    foreach ($job['attachments'] as $a) {
      $path = (string)($a['path'] ?? '');
      $name = (string)($a['name'] ?? 'file');
      if ($path === '' || !is_file($path)) continue;

      $mime = detect_mime_safely($path, $name);
      $size = (int)@filesize($path);
      $av   = antivirus_scan_detail($path);
      $verdict = ($av['status'] === 'infected') ? 'blocked' : 'attached';
      $sha256 = function_exists('hash_file') ? @hash_file('sha256', $path) : null;

      $scanReport[] = [
        'name'   => $name,
        'size'   => $size,
        'mime'   => $mime,
        'sha256' => $sha256,
        'engine' => $av['engine'],
        'av'     => $av['status'],
        'action' => $verdict,
      ];

      if ($verdict !== 'blocked') {
        $attachments[] = ['path'=>$path, 'name'=>$name];
      }
    }
  }

  // Append scan report to email body
  if (!empty($scanReport)) {
    $html .= '<div style="height:10px"></div><div style="padding:12px; border:1px solid #e6e6e6; border-radius:10px; background:#fafafa">'
          .  '<div style="font-weight:800; margin:0 0 8px; color:#58595b">Attachment scan report</div>'
          .  '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%; border-collapse:collapse; font-size:0.95rem">'
          .  '<tr style="background:#fff"><th align="left">File</th><th align="left">Size</th><th align="left">MIME</th><th align="left">AV</th><th align="left">Action</th></tr>';
    foreach ($scanReport as $r) {
      $sizeKB = number_format(($r['size'] ?? 0)/1024, 1).' KB';
      $avLab  = $r['av'].($r['engine'] ? ' ('.$r['engine'].')' : '');
      $sha    = !empty($r['sha256']) ? '<br><span style="color:#9aa0a6;font-size:.85em">sha256: '.safe((string)$r['sha256']).'</span>' : '';
      $html  .= '<tr style="background:#fff"><td>'.safe($r['name']).$sha.'</td><td>'.$sizeKB.'</td><td>'.safe($r['mime']).'</td><td>'.safe($avLab).'</td><td>'.safe($r['action']).'</td></tr>';
    }
    $html .= '</table></div>';

    $text .= "\n--- Attachment scan report ---\n";
    foreach ($scanReport as $r) {
      $sizeKB = number_format(($r['size'] ?? 0)/1024, 1).' KB';
      $avLab  = $r['av'].($r['engine'] ? ' ('.$r['engine'].')' : '');
      $text  .= "{$r['name']} | {$sizeKB} | {$r['mime']} | {$avLab} | {$r['action']}";
      if (!empty($r['sha256'])) $text .= " | sha256: {$r['sha256']}";
      $text .= "\n";
    }
  }

  send_mail_smtp2go(
    HELP_DESK_TO,    // defined in mail_common.php
    $email,          // reply-to
    $subject,
    $html,
    $text,
    $attachments
  );
}

// ----- main -----
if (php_sapi_name() !== 'cli') { wlog('refused: not CLI'); exit(0); }
$jobPath = $argv[1] ?? '';
if ($jobPath === '') { wlog('no job path'); exit(1); }

wlog("start job: $jobPath");
$job = read_job($jobPath);
if (!$job) { wlog('job read failed'); exit(1); }

try {
  $type = (string)($job['type'] ?? '');
  if ($type === 'contact') {
    send_contact($job);
  } elseif ($type === 'helpdesk') {
    send_helpdesk($job);
  } else {
    wlog('unknown job type: '.$type);
    throw new RuntimeException('unknown type');
  }
  wlog('job sent OK');
} catch (\Throwable $e) {
  wlog('ERROR sending job: '.$e->getMessage());
} finally {
  cleanup($job, $jobPath);
  wlog('cleanup done; exit');
}
