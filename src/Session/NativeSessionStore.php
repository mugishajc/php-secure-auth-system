<?php

declare(strict_types=1);

namespace SecureAuth\Session;

use RuntimeException;

/**
 * Session backed by PHP's own session handling, started with hardened
 * cookie and runtime settings.
 */
final class NativeSessionStore implements SessionStore
{
    public function __construct(private bool $secure = true)
    {
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // The __Host- prefix makes browsers reject the cookie unless it is
        // Secure, has Path=/ and no Domain, so a subdomain can't overwrite it.
        session_name($this->secure ? '__Host-sid' : 'sid');

        $options = [
            'use_strict_mode' => true,   // ignore session ids the server did not issue
            'use_only_cookies' => true,  // never accept ids from the URL
            'use_trans_sid' => false,
            'cookie_lifetime' => 0,      // browser-session cookie
            'cookie_path' => '/',
            'cookie_domain' => '',
            'cookie_secure' => $this->secure,
            'cookie_httponly' => true,   // not readable from JavaScript
            'cookie_samesite' => 'Lax',  // not sent on cross-site POSTs
            'sid_length' => 48,
            'sid_bits_per_character' => 6,
        ];

        // sid_length and sid_bits_per_character are deprecated as of PHP 8.4.
        if (PHP_VERSION_ID >= 80400) {
            unset($options['sid_length'], $options['sid_bits_per_character']);
        }

        if (!session_start($options)) {
            throw new RuntimeException('Could not start the session.');
        }
    }

    public function id(): string
    {
        $this->start();

        return (string) session_id();
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->start();

        return $_SESSION[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->start();
        $_SESSION[$key] = $value;
    }

    public function remove(string $key): void
    {
        $this->start();
        unset($_SESSION[$key]);
    }

    public function regenerate(): void
    {
        $this->start();
        // true deletes the old session file, so the old id is worthless.
        session_regenerate_id(true);
    }

    public function invalidate(): void
    {
        $this->start();
        $_SESSION = [];
        session_regenerate_id(true);
    }
}
