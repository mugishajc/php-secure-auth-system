<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

final class LoginResult
{
    private function __construct(
        public readonly LoginStatus $status,
        public readonly ?User $user = null,
        public readonly int $retryAfter = 0,
    ) {
    }

    public static function success(User $user): self
    {
        return new self(LoginStatus::Success, $user);
    }

    public static function invalid(): self
    {
        return new self(LoginStatus::InvalidCredentials);
    }

    public static function unverified(): self
    {
        return new self(LoginStatus::EmailNotVerified);
    }

    public static function throttled(int $retryAfter): self
    {
        return new self(LoginStatus::Throttled, null, $retryAfter);
    }

    public function succeeded(): bool
    {
        return $this->status === LoginStatus::Success;
    }

    /**
     * Message safe to show to the user. Invalid credentials never say
     * whether the email or the password was wrong.
     */
    public function message(): string
    {
        return match ($this->status) {
            LoginStatus::Success => 'Signed in.',
            LoginStatus::InvalidCredentials => 'Those credentials do not match our records.',
            LoginStatus::EmailNotVerified => 'Please verify your email address first. Check your inbox for the link.',
            LoginStatus::Throttled => sprintf('Too many attempts. Try again in %d minute(s).', (int) ceil($this->retryAfter / 60)),
        };
    }
}
