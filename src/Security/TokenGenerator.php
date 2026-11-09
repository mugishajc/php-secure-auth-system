<?php

declare(strict_types=1);

namespace SecureAuth\Security;

/**
 * One-time tokens for email links.
 *
 * The plain token goes into the email; only its SHA-256 hash is stored.
 * A token carries 256 bits of randomness, so a fast hash is enough here.
 * A slow password hash would only matter for low-entropy secrets.
 */
final class TokenGenerator
{
    public function generate(): string
    {
        return bin2hex(random_bytes(32));
    }

    public function hash(string $token): string
    {
        return hash('sha256', $token);
    }
}
