<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

use RuntimeException;

final class ValidationException extends RuntimeException
{
    /**
     * @param array<string, list<string>> $errors field => messages
     */
    public function __construct(public readonly array $errors)
    {
        parent::__construct('The given data was invalid.');
    }
}
