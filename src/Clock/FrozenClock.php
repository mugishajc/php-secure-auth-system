<?php

declare(strict_types=1);

namespace SecureAuth\Clock;

/**
 * A clock that only moves when told to. Used in tests for expiry and
 * throttling windows.
 */
final class FrozenClock implements Clock
{
    public function __construct(private int $now = 1_767_225_600)
    {
    }

    public function now(): int
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }
}
