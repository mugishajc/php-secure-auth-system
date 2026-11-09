<?php

declare(strict_types=1);

namespace SecureAuth\Mail;

final class InMemoryMailer implements Mailer
{
    /** @var list<array{to: string, subject: string, body: string}> */
    public array $sent = [];

    public function send(string $to, string $subject, string $body): void
    {
        $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
    }

    /**
     * @return array{to: string, subject: string, body: string}|null
     */
    public function last(): ?array
    {
        return $this->sent === [] ? null : $this->sent[array_key_last($this->sent)];
    }
}
