<?php

declare(strict_types=1);

namespace SecureAuth\Session;

interface SessionStore
{
    public function id(): string;

    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value): void;

    public function remove(string $key): void;

    /**
     * Issues a new session id and keeps the data. Must be called whenever
     * the privilege level changes (login) to prevent session fixation.
     */
    public function regenerate(): void;

    /**
     * Clears all data and issues a new id (logout).
     */
    public function invalidate(): void;
}
