<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

final class User
{
    public function __construct(
        public readonly int $id,
        public readonly string $email,
        public readonly string $name,
        public readonly string $passwordHash,
        public readonly ?int $emailVerifiedAt,
        public readonly int $sessionVersion,
    ) {
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            (int) $row['id'],
            (string) $row['email'],
            (string) $row['name'],
            (string) $row['password_hash'],
            $row['email_verified_at'] === null ? null : (int) $row['email_verified_at'],
            (int) $row['session_version'],
        );
    }

    public function isVerified(): bool
    {
        return $this->emailVerifiedAt !== null;
    }
}
