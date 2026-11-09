<?php

declare(strict_types=1);

namespace SecureAuth\Session;

/**
 * In-memory session for tests and CLI use.
 */
final class ArraySessionStore implements SessionStore
{
    private string $id;

    /** @var array<string, mixed> */
    private array $data = [];

    public function __construct()
    {
        $this->id = bin2hex(random_bytes(16));
    }

    public function id(): string
    {
        return $this->id;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function remove(string $key): void
    {
        unset($this->data[$key]);
    }

    public function regenerate(): void
    {
        $this->id = bin2hex(random_bytes(16));
    }

    public function invalidate(): void
    {
        $this->data = [];
        $this->regenerate();
    }
}
