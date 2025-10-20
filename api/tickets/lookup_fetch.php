<?php
declare(strict_types=1);
require __DIR__ . '/_lib.php';

tp_rate_check('lookup', tp_cfg()['rate_lookup_per_min']);

$token = $_GET['tkn'] ?? '';
if ($token === '') tp_error(400, 'Missing token.');
$claims = tp_parse_token($token);
$email  = $claims['email'];
$publicRef = $claims['public_ref'];

// Find ticket by public_ref (custom field) and email
$res = syncro('GET', '/tickets', ['custom_field_public_ref' => $publicRef, 'email'=>$email, 'per_page'=>1]);
$t = $res['tickets'][0] ?? null;
if (!$t) tp_error(404, 'Not found.');

$thread = [];
// Pull public communications only
$comments = syncro('GET', "/tickets/{$t['id']}/comments");
foreach ($comments['comments'] ?? [] as $c) {
  if (!($c['public'] ?? false)) continue;
  $thread[] = [
    'when' => $c['created_at'] ?? '',
    'author' => $c['author_name'] ?? 'Technician',
    'public' => true,
    'body_html' => htmlspecialchars($c['body'] ?? '', ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'),
  ];
}

tp_json([
  'public_ref' => $publicRef,
  'subject' => $t['subject'] ?? '',
  'status'  => $t['status'] ?? '',
  'updated_at' => $t['updated_at'] ?? '',
  'thread'  => $thread,
], 200);
