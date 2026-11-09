<?php

declare(strict_types=1);

namespace Tests\Integration;

use SecureAuth\Auth\AuthService;
use SecureAuth\Auth\ValidationException;

final class RegistrationTest extends AuthTestCase
{
    public function testRegisteringCreatesAnUnverifiedUserWithAnArgonHash(): void
    {
        $this->auth->register('  JC@Example.com ', 'Amina Uwase', self::PASSWORD);

        $user = $this->users->findByEmail('jc@example.com');

        $this->assertNotNull($user);
        $this->assertFalse($user->isVerified());
        $this->assertNotSame(self::PASSWORD, $user->passwordHash);
        $this->assertTrue(password_verify(self::PASSWORD, $user->passwordHash));
        if (defined('PASSWORD_ARGON2ID')) {
            $this->assertStringStartsWith('$argon2id$', $user->passwordHash);
        }
    }

    public function testVerificationEmailContainsALink(): void
    {
        $this->auth->register('jc@example.com', 'Amina Uwase', self::PASSWORD);

        $mail = $this->mailer->last();
        $this->assertSame('jc@example.com', $mail['to']);
        $this->assertStringContainsString('https://auth.test/verify-email?token=', $mail['body']);
    }

    public function testOnlyTheTokenHashIsStored(): void
    {
        $this->auth->register('jc@example.com', 'Amina Uwase', self::PASSWORD);
        $token = $this->tokenFromLastMail();

        $stored = $this->pdo->query('SELECT token_hash FROM user_tokens')->fetchAll(\PDO::FETCH_COLUMN);

        $this->assertSame([hash('sha256', $token)], $stored);
    }

    public function testVerificationTokenWorksOnce(): void
    {
        $this->auth->register('jc@example.com', 'Amina Uwase', self::PASSWORD);
        $token = $this->tokenFromLastMail();

        $this->assertTrue($this->auth->verifyEmail($token));
        $this->assertTrue($this->users->findByEmail('jc@example.com')->isVerified());
        $this->assertFalse($this->auth->verifyEmail($token));
    }

    public function testVerificationTokenExpiresAfter24Hours(): void
    {
        $this->auth->register('jc@example.com', 'Amina Uwase', self::PASSWORD);
        $token = $this->tokenFromLastMail();

        $this->clock->advance(AuthService::VERIFY_TOKEN_TTL + 1);

        $this->assertFalse($this->auth->verifyEmail($token));
        $this->assertFalse($this->users->findByEmail('jc@example.com')->isVerified());
    }

    public function testMadeUpTokensAreRejected(): void
    {
        $this->assertFalse($this->auth->verifyEmail(str_repeat('a', 64)));
        $this->assertFalse($this->auth->verifyEmail(''));
    }

    public function testDuplicateEmailDoesNotRevealTheAccount(): void
    {
        $this->auth->register('jc@example.com', 'Amina Uwase', self::PASSWORD);

        // No exception and no second account; the owner gets a heads-up instead.
        $this->auth->register('JC@example.com', 'Someone Else', 'another long passphrase');

        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        $this->assertSame('Sign-up attempt for your account', $this->mailer->last()['subject']);
        $this->assertSame('Amina Uwase', $this->users->findByEmail('jc@example.com')->name);
    }

    public function testInvalidInputIsReportedPerField(): void
    {
        try {
            $this->auth->register('not-an-email', '', 'short');
            $this->fail('Expected a ValidationException');
        } catch (ValidationException $e) {
            $this->assertSame(['email', 'name', 'password'], array_keys($e->errors));
        }

        $this->assertSame([], $this->mailer->sent);
    }

    public function testUserInputInSqlIsTreatedAsData(): void
    {
        $email = "o'brien+test@example.com";
        $this->auth->register($email, "Robert'); DROP TABLE users; --", self::PASSWORD);

        $user = $this->users->findByEmail($email);
        $this->assertNotNull($user);
        $this->assertSame("Robert'); DROP TABLE users; --", $user->name);
    }
}
