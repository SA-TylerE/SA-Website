<?php
// api/mail_worker.php
declare(strict_types=1);

require_once __DIR__.'/mail_common.php';

/**
 * Background worker:
 *  - argv[1] = absolute path to a job .json created by helpdesk.php/contact.php
 *  - Loads job, (optionally) scans attachments, composes HTML/text,
 *    sends via SMTP2GO, then deletes staged files + job file.
 *
 * Safe to run on Windows and Linux.
 */

/* ---------- Utility ---------- */
function safe_read_json(string $path): ?array {
  if (!is_file($path)) return null;
  $raw = @file_get_contents($path);
  if ($raw === false) return null;
  $data = json_decode($raw, true);
  return is_array($data) ? $data : null;
}
function cleanup_job(array $job, string $jobPath): void {
  if (!empty($job['attachments']) && is_array($job['attachments'])) {
    foreach ($job['attachments'] as $a) {
      if (!empty($a['path'])) @unlink($a['path']);
    }
  }
  @unlink($jobPath);
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
function antivirus_scan_detail(string $path): array {
  // Prefer absolute common locations; fall back to PATH
  $cands = [];
  foreach (['/usr/bin/clamdscan','/usr/local/bin/clamdscan','clamdscan'] as $bin) {
    if (@is_executable($bin) || trim(shell_exec("command -v $bin 2>/dev/null") ?? '') !== '') {
      $cands[] = [$bin, "$bin --no-summary --fdpass ".escapeshellarg($path), 'clamdscan'];
      break;
    }
  }
  foreach (['/usr/bin/clamscan','/usr/local/bin/clamscan','clamscan'] as $bin) {
    if (@is_executable($bin) || trim(shell_exec("command -v $bin 2>/dev/null") ?? '') !== '') {
      $cands[] = [$bin, "$bin --no-summary ".escapeshellarg($path), 'clamscan'];
      break;
    }
  }
  if (!$cands) return ['status'=>'unavailable','engine'=>null];

  foreach ($cands as [$bin,$cmd,$engine]) {
    $out = [];
    @exec($cmd, $out, $code);
    if ($code === 0) return ['status'=>'clean','engine'=>$engine];
    if ($code === 1) return ['status'=>'infected','engine'=>$engine];
    // try next candidate; if none, fall through as error
  }
  return ['status'=>'error','engine'=>null];
}
/* ---------------------------- */

if ($argc < 2) {
  // nothing to do
  exit(0);
}
$jobPath = $argv[1];
$job = safe_read_json($jobPath);
if (!$job) {
  error_log("mail_worker: bad job file: $jobPath");
  exit(0);
}

$type = $job['type'] ?? '';
$ip   = $job['ip']   ?? 'n/a';
$safe = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

try {
  if ($type === 'helpdesk') {
    // Compose Support email
    $name    = (string)($job['name']    ?? '');
    $company = (string)($job['company'] ?? '');
    $email   = (string)($job['email']   ?? '');
    $issue   = (string)($job['issue']   ?? '');

    $htmlIssue = nl2br($safe($issue));

    $html = '
      <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
        <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
          <h2 style="margin:0 0 12px">Support Form</h2>
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

    $text = "Support Form\n"
          . "From: $name\n"
          . "Company: $company\n"
          . "Email: $email\n"
          . "IP: $ip\n\n"
          . "$issue\n";

    // Scan & attach files
    $attachments = [];
    $scanReport  = [];
    $staged = is_array($job['attachments'] ?? null) ? $job['attachments'] : [];

    foreach ($staged as $f) {
      $path = (string)($f['path'] ?? '');
      $name = (string)($f['name'] ?? '');
      $size = (int)($f['size'] ?? 0);
      if ($path === '' || !is_file($path)) continue;

      $mime = detect_mime_safely($path, $name);
      $verdict = 'attached';
      $reason  = '';

      // mirror allowlist from endpoint (defense in depth)
      if ($size > 5 * 1024 * 1024) { $verdict='blocked'; $reason='too large'; }
      if (!preg_match('/\.(png|jpe?g|pdf|txt|log|docx?|xlsx|csv)$/i', $name)) { $verdict='blocked'; $reason='type not allowed'; }
      if ($verdict !== 'blocked' && !in_array($mime, [
        'image/png','image/jpeg','application/pdf','text/plain',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv'
      ], true)) { $verdict='blocked'; $reason='MIME check failed'; }

      $av = ['status'=>'unavailable','engine'=>null];
      if ($verdict !== 'blocked') {
        $av = antivirus_scan_detail($path);
        if ($av['status'] === 'infected') { $verdict='blocked'; $reason='virus detected'; }
        elseif ($av['status'] === 'error') { $reason='AV error (proceeded)'; }
      }

      $sha256 = function_exists('hash_file') ? @hash_file('sha256', $path) : null;

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
        $attachments[] = ['path'=>$path, 'name'=>$name];
      }
    }

    if (!empty($scanReport)) {
      $html .= '<div style="height:10px"></div>'
             . '<div style="padding:12px; border:1px solid #e6e6e6; border-radius:10px; background:#fafafa">'
             . '<div style="font-weight:800; margin:0 0 8px; color:#58595b">Attachment scan report</div>'
             . '<table role="presentation" cellpadding="6" cellspacing="0" style="width:100%; border-collapse:collapse; font-size:0.95rem">'
             . '<tr style="background:#fff"><th align="left">File</th><th align="left">Size</th><th align="left">MIME</th><th align="left">AV</th><th align="left">Action</th></tr>';
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

    $subject = "Support Form: New request";
    send_mail_smtp2go(
      HELP_DESK_TO,
      $email,
      $subject,
      $html,
      $text,
      $attachments
    );
  }
  elseif ($type === 'contact') {
    $name    = (string)($job['name']    ?? '');
    $company = (string)($job['company'] ?? '');
    $email   = (string)($job['email']   ?? '');
    $phone   = (string)($job['phone']   ?? '');
    $subject = (string)($job['subject'] ?? '');
    $message = (string)($job['message'] ?? '');

    $htmlMessage = nl2br($safe($message));

    $html = '
      <div style="font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#231f20;">
        <div style="padding:16px 18px; border:1px solid #e6e6e6; border-radius:12px;">
          <h2 style="margin:0 0 12px">Contact Form: '. $safe($subject) .'</h2>
          <table role="presentation" cellspacing="0" cellpadding="0" style="width:100%; border-collapse:collapse; margin:0 0 12px">
            <tr><td style="padding:6px 0; font-weight:700; width:120px;">From</td><td style="padding:6px 0;">'.$safe($name).'</td></tr>
            <tr><td style="padding:6px 0; font-weight:700;">Company</td><td style="padding:6px 0;">'.$safe($company).'</td></tr>
            <tr><td style="padding:6px 0; font-weight:700;">Email</td><td style="padding:6px 0;"><a href="mailto:'.$safe($email).'" style="color:#aa1e2e">'.$safe($email).'</a></td></tr>
            <tr><td style="padding:6px 0; font-weight:700;">Phone</td><td style="padding:6px 0;">'.($phone !== '' ? $safe($phone) : '<span style="color:#9aa0a6">n/a</span>').'</td></tr>
            <tr><td style="padding:6px 0; font-weight:700;">IP</td><td style="padding:6px 0;">'.$safe($ip).'</td></tr>
          </table>
          <div style="border-top:1px solid #e6e6e6; margin:10px 0 12px"></div>
          <div>
            <div style="font-weight:700; margin:0 0 6px">Message</div>
            <div style="white-space:pre-wrap; line-height:1.5">'.$htmlMessage.'</div>
          </div>
        </div>
      </div>';

    $text = "Contact Form: $subject\n"
          . "From: $name\n"
          . "Company: $company\n"
          . "Email: $email\n"
          . "Phone: " . ($phone !== '' ? $phone : 'n/a') . "\n"
          . "IP: $ip\n\n"
          . "$message\n";

    $subjectLine = "Contact Form: $subject";
    send_mail_smtp2go(
      CONTACT_TO,
      $email,
      $subjectLine,
      $html,
      $text
    );
  }
  else {
    error_log("mail_worker: unknown job type for $jobPath");
  }
} catch (Throwable $e) {
  error_log("mail_worker exception: ".$e->getMessage());
} finally {
  cleanup_job($job, $jobPath);
}
