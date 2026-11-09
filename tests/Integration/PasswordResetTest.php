<?php

declare(strict_types=1);

namespace Tests\Integration;

use SecureAuth\Auth\AuthService;
use SecureAuth\Auth\ValidationException;
use SecureAuth\Session\ArraySessionStore;

final class PasswordResetTest extends AuthTestCase
{
    private const NEW_PASSWORD = 'green door at the end of the hall';

    public function testUnknownEmailsGetNoMailAndNoError(): void
    {
        $this->auth->requestPasswordReset('nobody@example.com', '10.0.0.1');

        $this->assertSame([], $this->mailer->sent);
    }

    public function testResetLinkIsEmailed(): void
    {
        $this->registerVerifiedUser();

        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');

        $mail = $this->mailer->last();
        $this->assertSame('Reset your password', $mail['subject']);
        $this->assertStringContainsString('https://auth.test/reset-password?token=', $mail['body']);
    }

    public function testResettingChangesThePassword(): void
    {
        $this->registerVerifiedUser();
        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        $token = $this->tokenFromLastMail();

        $this->assertTrue($this->auth->isValidResetToken($token));
        $this->assertTrue($this->auth->resetPassword($token, self::NEW_PASSWORD));

        $this->assertFalse($this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1')->succeeded());
        $this->assertTrue($this->auth->attempt('jc@example.com', self::NEW_PASSWORD, '10.0.0.1')->succeeded());
        $this->assertSame('Your password was changed', $this->mailer->last()['subject']);
    }

    public function testResetTokenCannotBeReused(): void
    {
        $this->registerVerifiedUser();
        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        $token = $this->tokenFromLastMail();

        $this->assertTrue($this->auth->resetPassword($token, self::NEW_PASSWORD));
        $this->assertFalse($this->auth->resetPassword($token, 'yet another long passphrase'));
        $this->assertFalse($this->auth->isValidResetToken($token));
    }

    public function testResetTokenExpiresAfterAnHour(): void
    {
        $this->registerVerifiedUser();
        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        $token = $this->tokenFromLastMail();

        $this->clock->advance(AuthService::RESET_TOKEN_TTL + 1);

        $this->assertFalse($this->auth->resetPassword($token, self::NEW_PASSWORD));
    }

    public function testOnlyTheNewestResetLinkWorks(): void
    {
        $this->registerVerifiedUser();
        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        $first = $this->tokenFromLastMail();
        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        $second = $this->tokenFromLastMail();

        $this->assertFalse($this->auth->isValidResetToken($first));
        $this->assertTrue($this->auth->isValidResetToken($second));
    }

    public function testWeakNewPasswordIsRejectedAndTokenSurvives(): void
    {
        $this->registerVerifiedUser();
        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        $token = $this->tokenFromLastMail();

        try {
            $this->auth->resetPassword($token, 'short');
            $this->fail('Expected a ValidationException');
        } catch (ValidationException $e) {
            $this->assertArrayHasKey('password', $e->errors);
        }

        $this->assertTrue($this->auth->isValidResetToken($token));
    }

    public function testResetSignsOutExistingSessions(): void
    {
        $this->registerVerifiedUser();

        $laptop = new ArraySessionStore();
        $laptopAuth = $this->makeAuth($laptop);
        $this->assertTrue($laptopAuth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1')->succeeded());
        $this->assertNotNull($laptopAuth->user());

        $this->auth->requestPasswordReset('jc@example.com', '10.0.0.2');
        $this->auth->resetPassword($this->tokenFromLastMail(), self::NEW_PASSWORD);

        $this->assertNull($laptopAuth->user());
    }

    public function testResetVerifiesTheEmail(): void
    {
        $this->auth->register('new@example.com', 'New Person', self::PASSWORD);
        $this->auth->requestPasswordReset('new@example.com', '10.0.0.1');

        $this->assertTrue($this->auth->resetPassword($this->tokenFromLastMail(), self::NEW_PASSWORD));
        $this->assertTrue($this->auth->attempt('new@example.com', self::NEW_PASSWORD, '10.0.0.1')->succeeded());
    }

    public function testResetRequestsAreRateLimitedPerEmail(): void
    {
        $this->registerVerifiedUser();
        $before = count($this->mailer->sent);

        for ($i = 0; $i < AuthService::MAX_RESET_REQUESTS + 2; $i++) {
            $this->auth->requestPasswordReset('jc@example.com', '10.0.0.1');
        }

        $this->assertCount($before + AuthService::MAX_RESET_REQUESTS, $this->mailer->sent);
    }
}
