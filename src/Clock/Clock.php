<?php

declare(strict_types=1);

namespace SecureAuth\Clock;

interface Clock
{
    /** Current time as a unix timestamp. */
    public function now(): int;
}
