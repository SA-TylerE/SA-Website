<?php // /api/tickets/_config.php
declare(strict_types=1);

return [
  // Your Syncro subdomain and API token
  'syncro_base' => 'https://YOURSUBDOMAIN.syncromsp.com',
  'syncro_token' => 'YOUR_API_TOKEN',

  // Email sender for magic links (use your existing mailer)
  'from_email' => 'support@systemalternatives.net',
  'from_name'  => 'System Alternatives Support',

  // Magic link JWT/HMAC secret (32+ random bytes)
  'lookup_secret' => 'CHANGE_ME_LONG_RANDOM',

  // Magic link TTL (seconds)
  'lookup_ttl' => 15 * 60,

  // Rate limits (IP based)
  'rate_create_per_min' => 5,
  'rate_lookup_per_min' => 5,

  // Attachment limits
  'max_files' => 5,
  'max_bytes_per_file' => 15 * 1024 * 1024,
  'allowed_ext' => ['png','jpg','jpeg','pdf','txt','log','doc','docx','xlsx','csv'],

  // Optional captcha verify endpoint key (if you enable one)
  'captcha' => [
    'enabled' => false,
    'provider' => 'turnstile', // or 'hcaptcha' | 'recaptcha'
    'secret' => 'CAPTCHA_SECRET',
  ],
];
