<?php

declare(strict_types=1);

// Reads settings from the environment, falling back to a local .env file.
$env = [];
$file = __DIR__ . '/.env';
if (is_file($file)) {
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $env[trim($key)] = trim($value);
    }
}

$get = static fn (string $key, string $default): string => getenv($key) !== false ? (string) getenv($key) : ($env[$key] ?? $default);

$dsn = $get('DB_DSN', 'sqlite:storage/auth.sqlite');
// Relative SQLite paths are resolved from the project root.
if (str_starts_with($dsn, 'sqlite:') && !str_starts_with($dsn, 'sqlite:/') && $dsn !== 'sqlite::memory:') {
    $dsn = 'sqlite:' . __DIR__ . '/' . substr($dsn, 7);
}

$mailLog = $get('MAIL_LOG', 'storage/mail.log');

return [
    'app_url' => rtrim($get('APP_URL', 'http://localhost:8000'), '/'),
    'db_dsn' => $dsn,
    'session_secure' => $get('SESSION_SECURE', '0') === '1',
    'mail_log' => str_starts_with($mailLog, '/') ? $mailLog : __DIR__ . '/' . $mailLog,
];
