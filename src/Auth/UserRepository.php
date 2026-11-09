<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

use PDO;

/**
 * All queries use prepared statements with bound parameters.
 */
final class UserRepository
{
    public function __construct(private PDO $pdo)
    {
    }

    public function findById(int $id): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();

        return $row === false ? null : User::fromRow($row);
    }

    public function findByEmail(string $email): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = :email');
        $stmt->execute(['email' => $email]);
        $row = $stmt->fetch();

        return $row === false ? null : User::fromRow($row);
    }

    public function create(string $email, string $name, string $passwordHash, int $now): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (email, name, password_hash, created_at, updated_at)
             VALUES (:email, :name, :hash, :now, :now2)'
        );
        $stmt->execute(['email' => $email, 'name' => $name, 'hash' => $passwordHash, 'now' => $now, 'now2' => $now]);

        return (int) $this->pdo->lastInsertId();
    }

    public function markVerified(int $id, int $now): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET email_verified_at = :now, updated_at = :now2 WHERE id = :id AND email_verified_at IS NULL'
        );
        $stmt->execute(['now' => $now, 'now2' => $now, 'id' => $id]);
    }

    /**
     * Replaces the hash after a rehash. Existing sessions stay valid.
     */
    public function updateHash(int $id, string $hash, int $now): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET password_hash = :hash, updated_at = :now WHERE id = :id');
        $stmt->execute(['hash' => $hash, 'now' => $now, 'id' => $id]);
    }

    /**
     * Sets a new password and bumps session_version, which signs out
     * every session that was opened with the old password.
     */
    public function changePassword(int $id, string $hash, int $now): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET password_hash = :hash, session_version = session_version + 1, updated_at = :now WHERE id = :id'
        );
        $stmt->execute(['hash' => $hash, 'now' => $now, 'id' => $id]);
    }
}
