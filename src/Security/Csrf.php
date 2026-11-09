<?php

declare(strict_types=1);

namespace SecureAuth\Security;

use SecureAuth\Session\SessionStore;

/**
 * Synchronizer-token CSRF protection. One random token per session,
 * rotated on login and logout.
 */
final class Csrf
{
    private const KEY = '_csrf';

    public function __construct(private SessionStore $session)
    {
    }

    public function token(): string
    {
        $token = $this->session->get(self::KEY);

        if (!is_string($token) || strlen($token) !== 64) {
            $token = $this->rotate();
        }

        return $token;
    }

    public function rotate(): string
    {
        $token = bin2hex(random_bytes(32));
        $this->session->set(self::KEY, $token);

        return $token;
    }

    public function validate(mixed $submitted): bool
    {
        if (!is_string($submitted) || $submitted === '') {
            return false;
        }

        return hash_equals($this->token(), $submitted);
    }

    public function field(): string
    {
        return '<input type="hidden" name="_csrf" value="' . e($this->token()) . '">';
    }
}
