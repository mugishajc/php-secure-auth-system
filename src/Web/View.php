<?php

declare(strict_types=1);

namespace SecureAuth\Web;

use RuntimeException;

/**
 * Minimal template renderer. Templates escape their own output with e().
 */
final class View
{
    public function __construct(private string $directory)
    {
    }

    /**
     * @param array<string, mixed> $data
     */
    public function render(string $template, array $data = []): string
    {
        $content = $this->include($template, $data);

        return $this->include('layout', ['content' => $content] + $data);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function include(string $template, array $data): string
    {
        if (preg_match('/^[a-z][a-z0-9_-]*$/', $template) !== 1) {
            throw new RuntimeException("Invalid template name [$template]");
        }

        $path = $this->directory . '/' . $template . '.php';
        if (!is_file($path)) {
            throw new RuntimeException("Template [$template] not found");
        }

        $render = static function (string $__path, array $__data): string {
            extract($__data, EXTR_SKIP);
            ob_start();
            try {
                require $__path;
            } finally {
                $output = (string) ob_get_clean();
            }

            return $output;
        };

        return $render($path, $data);
    }
}
