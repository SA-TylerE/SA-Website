<?php
declare(strict_types=1);

// Load config
function tp_cfg(): array {
  static $cfg = null;
  if ($cfg === null) $cfg = require __DIR__ . '/_config.php';
  return $cfg;
}

function tp_ip(): string {
  return $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// Simple IP rate limiting using temp files (swap for Redis if you want)
function tp_rate_check(string $bucket, int $limitPerMin): void {
  $dir = sys_get_temp_dir() . '/tp_rate';
  if (!is_dir($dir)) @mkdir($dir, 0700, true);
  $key = sprintf('%s/%s_%s_%s', $dir, $bucket, date('YmdHi'), sha1(tp_ip()));
  $count = is_file($key) ? (int)file_get_contents($key) : 0;
  if ($count >= $limitPerMin) tp_error(429, 'Slow down.');
  file_put_contents($key, (string)($count + 1), LOCK_EX);
}

// Minimal JSON reply helpers
function tp_json($data, int $code=200): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
  exit;
}
function tp_error(int $code, string $msg): void { tp_json(['error'=>$msg], $code); }

// Syncro API wrapper
function syncro(string $method, string $path, array $query=[], $body=null) {
  $cfg = tp_cfg();
  $url = rtrim($cfg['syncro_base'],'/') . '/api/v1' . $path;
  if ($query) $url .= '?' . http_build_query($query);

  $ch = curl_init($url);
  $headers = [
    'Accept: application/json',
    'Content-Type: application/json',
    'Authorization: Bearer ' . $cfg['syncro_token'],
  ];
  curl_setopt_array($ch, [
    CURLOPT_CUSTOMREQUEST => strtoupper($method),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_TIMEOUT => 20,
  ]);
  if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
  $resp = curl_exec($ch);
  if ($resp === false) tp_error(502, 'Upstream error');
  $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  $data = json_decode($resp, true);
  if ($status >= 400) tp_error($status, $data['error'] ?? 'Syncro error');
  return $data;
}

// Public ref generator (short, user-facing). We store it on ticket create (custom field).
function tp_public_ref(): string {
  // 6-char base32, avoids ambiguous chars.
  $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  $ref = '';
  for ($i=0; $i<6; $i++) $ref .= $alphabet[random_int(0, strlen($alphabet)-1)];
  return $ref;
}

// HMAC token for magic link (no dependency on JWT libs)
function tp_make_token(array $claims, int $ttl): string {
  $cfg = tp_cfg();
  $claims['exp'] = time() + $ttl;
  $payload = base64_encode(json_encode($claims));
  $sig = hash_hmac('sha256', $payload, $cfg['lookup_secret']);
  return $payload . '.' . $sig;
}
function tp_parse_token(string $token): array {
  $cfg = tp_cfg();
  if (!str_contains($token, '.')) tp_error(400, 'Bad token');
  [$payload, $sig] = explode('.', $token, 2);
  $calc = hash_hmac('sha256', $payload, $cfg['lookup_secret']);
  if (!hash_equals($calc, $sig)) tp_error(401, 'Invalid token');
  $claims = json_decode(base64_decode($payload), true);
  if (!$claims || ($claims['exp'] ?? 0) < time()) tp_error(401, 'Expired token');
  return $claims;
}

// Very conservative attachment screening
function tp_validate_and_scan_files(array $cfg): array {
  $safeFiles = [];
  if (!isset($_FILES['files'])) return $safeFiles;
  $files = $_FILES['files'];
  $count = is_array($files['name']) ? count($files['name']) : 0;
  if ($count > $cfg['max_files']) tp_error(400, 'Too many files.');
  for ($i=0; $i<$count; $i++) {
    if ($files['error'][$i] !== UPLOAD_ERR_OK) tp_error(400, 'Upload error.');
    $name = $files['name'][$i];
    $tmp  = $files['tmp_name'][$i];
    $size = (int)$files['size'][$i];
    $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if ($size <= 0 || $size > $cfg['max_bytes_per_file']) tp_error(400, 'File too large.');
    if (!in_array($ext, $cfg['allowed_ext'], true)) tp_error(400, 'Disallowed file type.');

    // AV scan hook (your existing function)
    if (function_exists('antivirus_scan_detail')) {
      $av = antivirus_scan_detail($tmp);
      if (($av['status'] ?? '') !== 'clean') tp_error(400, 'Attachment blocked by antivirus.');
    }

    $safeFiles[] = ['path'=>$tmp, 'name'=>$name];
  }
  return $safeFiles;
}

// Minimal mail sender (replace with your existing SMTP2GO/mailer)
function tp_send_magic_link(string $to, string $publicRef, string $token): void {
  $cfg = tp_cfg();
  $link = rtrim($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'], '/') . '/support.html?tkn=' . urlencode($token);
  $subject = "Secure ticket link (#$publicRef)";
  $body = "Click to view your ticket securely:\n\n$link\n\nThis link expires in " . (tp_cfg()['lookup_ttl']/60) . " minutes.";
  // Use your existing mailer here; below is PHP mail() as a placeholder.
  @mail($to, $subject, $body, "From: {$cfg['from_name']} <{$cfg['from_email']}>");
}
