<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

use PDO;

final class TokenRepository
{
    public const VERIFY_EMAIL = 'verify_email';
    public const PASSWORD_RESET = 'password_reset';

    public function __construct(private PDO $pdo)
    {
    }

    public function create(int $userId, string $type, string $tokenHash, int $expiresAt, int $now): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_tokens (user_id, type, token_hash, expires_at, created_at)
             VALUES (:user_id, :type, :hash, :expires_at, :now)'
        );
        $stmt->execute([
            'user_id' => $userId,
            'type' => $type,
            'hash' => $tokenHash,
            'expires_at' => $expiresAt,
            'now' => $now,
        ]);
    }

    /**
     * Finds an unused, unexpired token of the given type.
     *
     * @return array{id: int, user_id: int}|null
     */
    public function findValid(string $type, string $tokenHash, int $now): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, user_id FROM user_tokens
             WHERE type = :type AND token_hash = :hash AND used_at IS NULL AND expires_at > :now'
        );
        $stmt->execute(['type' => $type, 'hash' => $tokenHash, 'now' => $now]);
        $row = $stmt->fetch();

        return $row === false ? null : ['id' => (int) $row['id'], 'user_id' => (int) $row['user_id']];
    }

    /**
     * Marks a token as used. Returns false if it was already used, which
     * stops two concurrent requests from both redeeming it.
     */
    public function consume(int $id, int $now): bool
    {
        $stmt = $this->pdo->prepare('UPDATE user_tokens SET used_at = :now WHERE id = :id AND used_at IS NULL');
        $stmt->execute(['now' => $now, 'id' => $id]);

        return $stmt->rowCount() === 1;
    }

    public function deleteForUser(int $userId, string $type): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM user_tokens WHERE user_id = :user_id AND type = :type');
        $stmt->execute(['user_id' => $userId, 'type' => $type]);
    }
}
