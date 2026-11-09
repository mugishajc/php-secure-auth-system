<?php

declare(strict_types=1);

namespace SecureAuth\Mail;

/**
 * Development mailer: appends messages to a file instead of sending them,
 * so verification and reset links can be opened locally.
 */
final class LogMailer implements Mailer
{
    public function __construct(private string $path)
    {
    }

    public function send(string $to, string $subject, string $body): void
    {
        $entry = sprintf(
            "----\nDate: %s\nTo: %s\nSubject: %s\n\n%s\n",
            gmdate('D, d M Y H:i:s') . ' +0000',
            $to,
            $subject,
            $body,
        );

        file_put_contents($this->path, $entry, FILE_APPEND | LOCK_EX);
    }
}
