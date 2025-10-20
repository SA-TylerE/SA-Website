<?php
declare(strict_types=1);
require __DIR__ . '/_lib.php';

tp_rate_check('create', tp_cfg()['rate_create_per_min']);

$cfg = tp_cfg();
$name = trim($_POST['name'] ?? '');
$email = trim($_POST['email'] ?? '');
$company = trim($_POST['company'] ?? '');
$subject = trim($_POST['subject'] ?? '');
$issue = trim($_POST['issue'] ?? '');

if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $subject === '' || $issue === '') {
  tp_error(400, 'Invalid input.');
}

// CAPTCHA (optional)
if (($cfg['captcha']['enabled'] ?? false) === true) {
  // Verify token from POST e.g., $_POST['cf-turnstile-response']
  // ... implement provider verification using $cfg['captcha']['secret']
}

// Validate + AV scan attachments
$attachments = tp_validate_and_scan_files($cfg);

// Generate a public reference and store to Syncro via a custom field or tags
$publicRef = tp_public_ref();

// Build Syncro ticket create payload (adjust to your exact API fields)
$payload = [
  'subject' => $subject,
  'status'  => 'New',
  'problem_type' => 'Support',
  'requester' => [
    'name'  => $name,
    'email' => $email,
    'organization_name' => $company ?: null,
  ],
  'custom_fields' => [
    'public_ref' => $publicRef,
  ],
  'initial_comment' => [
    'body' => $issue,
    'public' => true,
    'do_not_email' => false
  ],
];

$ticket = syncro('POST', '/tickets', [], $payload);
$ticketId = $ticket['id'] ?? null;
if (!$ticketId) tp_error(502, 'Ticket creation failed.');

// If attachments exist, upload to the ticket
foreach ($attachments as $f) {
  // Some Syncro uploads are multipart; if your API requires multipart, use a separate cURL call here.
  // Placeholder: uploading as public comment:
  $body = [
    'body' => "Attachment: {$f['name']}",
    'public' => true,
    'do_not_email' => false,
  ];
  syncro('POST', "/tickets/{$ticketId}/comments", [], $body);
  // TODO: real file upload endpoint if supported in your tenant (adjust docs).
}

// Email a confirmation with the publicRef (and optionally the magic link)
$token = tp_make_token(['email'=>$email, 'public_ref'=>$publicRef], $cfg['lookup_ttl']);
tp_send_magic_link($email, $publicRef, $token);

tp_json(['ok'=>true, 'public_ref'=>$publicRef, 'id'=>$ticketId], 201);
