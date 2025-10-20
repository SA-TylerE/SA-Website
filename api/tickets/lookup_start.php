<?php
declare(strict_types=1);
require __DIR__ . '/_lib.php';

tp_rate_check('lookup', tp_cfg()['rate_lookup_per_min']);

$email = trim($_POST['email'] ?? '');
$ticketNumber = trim($_POST['ticket_number'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) tp_error(400, 'Invalid input.');

// If ticket number provided, try to find that one belonging to the email; else, find the most recent for that email
// NOTE: You must tune the query to your Syncro API (filter by requester email).
$found = null;
if ($ticketNumber !== '') {
  // Example: GET /tickets?number=XYZ
  $res = syncro('GET', '/tickets', ['number'=>$ticketNumber]);
  $t = $res['tickets'][0] ?? null;
  if ($t && strcasecmp($t['requester']['email'] ?? '', $email) === 0) $found = $t;
} else {
  // Example: GET /tickets?email=...
  $res = syncro('GET', '/tickets', ['email'=>$email, 'order'=>'updated_at_desc', 'per_page'=>1]);
  $found = $res['tickets'][0] ?? null;
}

if ($found) {
  $publicRef = $found['custom_fields']['public_ref'] ?? tp_public_ref();
  // If missing (older tickets), you might backfill it here by PATCHing the ticket.
  $token = tp_make_token(['email'=>$email, 'public_ref'=>$publicRef], tp_cfg()['lookup_ttl']);
  tp_send_magic_link($email, $publicRef, $token);
}

// Always reply neutral
tp_json(['ok'=>true]);
