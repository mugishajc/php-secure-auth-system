<?php

declare(strict_types=1);

namespace SecureAuth\Security;

/**
 * Length-based policy in the spirit of NIST SP 800-63B: a reasonable
 * minimum, a generous maximum, and a block list of passwords that show up
 * first in every cracking dictionary. No composition rules.
 */
final class PasswordPolicy
{
    public const MIN_LENGTH = 12;

    // Long enough for passphrases, short enough that hashing can't be used for DoS.
    public const MAX_LENGTH = 256;

    private const COMMON = [
        '123456789012', 'password1234', 'qwertyuiop12', '111111111111', 'iloveyou1234',
        'passwordpassword', 'qwerty123456', '1q2w3e4r5t6y', 'adminadmin12', 'letmein12345',
        'welcome12345', 'abc123456789', 'changeme1234', 'password123!', 'p@ssw0rd1234',
    ];

    /**
     * @return list<string> human readable problems, empty when the password is acceptable
     */
    public function check(string $password, ?string $email = null): array
    {
        $errors = [];
        $length = mb_strlen($password);

        if ($length < self::MIN_LENGTH) {
            $errors[] = 'Password must be at least ' . self::MIN_LENGTH . ' characters.';
        }

        if ($length > self::MAX_LENGTH) {
            $errors[] = 'Password must be at most ' . self::MAX_LENGTH . ' characters.';
        }

        if (in_array(mb_strtolower($password), self::COMMON, true)) {
            $errors[] = 'This password is too common.';
        }

        if ($length > 0 && count(array_unique(mb_str_split($password))) === 1) {
            $errors[] = 'Password must not be a single repeated character.';
        }

        if ($email !== null && $email !== '') {
            $local = mb_strtolower(explode('@', $email)[0]);
            if (mb_strlen($local) >= 4 && str_contains(mb_strtolower($password), $local)) {
                $errors[] = 'Password must not contain your email address.';
            }
        }

        return $errors;
    }
}
