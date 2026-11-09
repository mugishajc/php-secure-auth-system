<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

use PDO;
use SecureAuth\Clock\Clock;

/**
 * Sliding-window rate limiter for login and reset attempts, stored in
 * the database so it works across PHP workers.
 *
 * Keys are hashed before storage so the table never holds raw emails
 * or IP addresses.
 */
final class LoginThrottle
{
    public function __construct(
        private PDO $pdo,
        private Clock $clock,
        private int $windowSeconds = 900,
    ) {
    }

    public static function key(string ...$parts): string
    {
        return hash('sha256', implode('|', $parts));
    }

    public function hit(string $key): void
    {
        $now = $this->clock->now();

        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (throttle_key, attempted_at) VALUES (:key, :now)');
        $stmt->execute(['key' => $key, 'now' => $now]);

        // Housekeeping: anything outside the window no longer counts.
        $stmt = $this->pdo->prepare('DELETE FROM login_attempts WHERE attempted_at <= :cutoff');
        $stmt->execute(['cutoff' => $now - $this->windowSeconds]);
    }

    public function attempts(string $key): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM login_attempts WHERE throttle_key = :key AND attempted_at > :cutoff'
        );
        $stmt->execute(['key' => $key, 'cutoff' => $this->clock->now() - $this->windowSeconds]);

        return (int) $stmt->fetchColumn();
    }

    public function tooManyAttempts(string $key, int $maxAttempts): bool
    {
        return $this->attempts($key) >= $maxAttempts;
    }

    /**
     * Seconds until the oldest attempt in the window expires.
     */
    public function availableIn(string $key): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT MIN(attempted_at) FROM login_attempts WHERE throttle_key = :key AND attempted_at > :cutoff'
        );
        $now = $this->clock->now();
        $stmt->execute(['key' => $key, 'cutoff' => $now - $this->windowSeconds]);
        $oldest = $stmt->fetchColumn();

        if ($oldest === null || $oldest === false) {
            return 0;
        }

        return max(0, (int) $oldest + $this->windowSeconds - $now);
    }

    public function clear(string $key): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM login_attempts WHERE throttle_key = :key');
        $stmt->execute(['key' => $key]);
    }
}
