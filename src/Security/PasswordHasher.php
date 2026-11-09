<?php

declare(strict_types=1);

namespace SecureAuth\Security;

/**
 * Wraps password_hash() with Argon2id. Falls back to bcrypt only on PHP
 * builds compiled without Argon2 support.
 */
final class PasswordHasher
{
    private string $algorithm;

    /** @var array<string, int> */
    private array $options;

    /**
     * @param array<string, int> $argonOptions memory_cost (KiB), time_cost, threads
     */
    public function __construct(array $argonOptions = [])
    {
        if (defined('PASSWORD_ARGON2ID')) {
            $this->algorithm = PASSWORD_ARGON2ID;
            $this->options = $argonOptions + [
                'memory_cost' => 65536, // 64 MiB
                'time_cost' => 4,
                'threads' => 1,
            ];
        } else {
            $this->algorithm = PASSWORD_BCRYPT;
            $this->options = ['cost' => 12];
        }
    }

    public function hash(string $password): string
    {
        return password_hash($password, $this->algorithm, $this->options);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * True when the hash was made with another algorithm or older cost
     * settings. Checked after a successful login so stored hashes get
     * upgraded over time.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }
}
