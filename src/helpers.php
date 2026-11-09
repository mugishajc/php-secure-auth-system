<?php

declare(strict_types=1);

if (!function_exists('e')) {
    /**
     * Escapes a value for HTML text and quoted attribute contexts.
     * Not safe for unquoted attributes, URLs in href, or inline scripts.
     */
    function e(mixed $value): string
    {
        if ($value === null) {
            return '';
        }

        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
