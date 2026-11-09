<?php

declare(strict_types=1);

namespace SecureAuth\Web;

final class SecurityHeaders
{
    /**
     * @return array<string, string>
     */
    public static function all(bool $https): array
    {
        $headers = [
            'Content-Security-Policy' => "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            // Reset links carry a token in the URL; never leak it through Referer.
            'Referrer-Policy' => 'no-referrer',
            // Pages with account data or tokens shouldn't sit in shared caches.
            'Cache-Control' => 'no-store',
        ];

        if ($https) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
        }

        return $headers;
    }

    public static function send(bool $https): void
    {
        foreach (self::all($https) as $name => $value) {
            header("$name: $value");
        }
    }
}
