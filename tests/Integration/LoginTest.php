<?php

declare(strict_types=1);

namespace Tests\Integration;

use SecureAuth\Auth\AuthService;
use SecureAuth\Auth\LoginStatus;
use SecureAuth\Security\PasswordHasher;

final class LoginTest extends AuthTestCase
{
    public function testUnverifiedUsersCannotSignIn(): void
    {
        $this->auth->register('jc@example.com', 'Jean Claude', self::PASSWORD);

        $result = $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1');

        $this->assertSame(LoginStatus::EmailNotVerified, $result->status);
        $this->assertNull($this->auth->user());
    }

    public function testSuccessfulLoginStartsASession(): void
    {
        $this->registerVerifiedUser();

        $result = $this->auth->attempt('JC@example.com', self::PASSWORD, '10.0.0.1');

        $this->assertTrue($result->succeeded());
        $this->assertSame('jc@example.com', $this->auth->user()?->email);
    }

    public function testLoginRegeneratesTheSessionId(): void
    {
        $this->registerVerifiedUser();
        $before = $this->session->id();

        $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1');

        $this->assertNotSame($before, $this->session->id());
    }

    public function testWrongPasswordAndUnknownEmailLookTheSame(): void
    {
        $this->registerVerifiedUser();

        $wrongPassword = $this->auth->attempt('jc@example.com', 'not the password at all', '10.0.0.1');
        $unknownEmail = $this->auth->attempt('nobody@example.com', self::PASSWORD, '10.0.0.1');

        $this->assertSame(LoginStatus::InvalidCredentials, $wrongPassword->status);
        $this->assertSame(LoginStatus::InvalidCredentials, $unknownEmail->status);
        $this->assertSame($wrongPassword->message(), $unknownEmail->message());
        $this->assertNull($this->auth->user());
    }

    public function testAccountIsThrottledAfterFiveFailures(): void
    {
        $this->registerVerifiedUser();

        for ($i = 0; $i < AuthService::MAX_ATTEMPTS_PER_ACCOUNT; $i++) {
            $this->auth->attempt('jc@example.com', 'wrong password ' . $i, '10.0.0.1');
        }

        // Even the right password is refused while throttled.
        $result = $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1');
        $this->assertSame(LoginStatus::Throttled, $result->status);
        $this->assertSame(900, $result->retryAfter);
        $this->assertNull($this->auth->user());

        // A different IP has its own counter for this account.
        $this->assertTrue($this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.2')->succeeded());
    }

    public function testThrottleLiftsAfterTheWindow(): void
    {
        $this->registerVerifiedUser();

        for ($i = 0; $i < AuthService::MAX_ATTEMPTS_PER_ACCOUNT; $i++) {
            $this->auth->attempt('jc@example.com', 'wrong password ' . $i, '10.0.0.1');
        }

        $this->clock->advance(901);

        $this->assertTrue($this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1')->succeeded());
    }

    public function testSuccessResetsTheAccountCounter(): void
    {
        $this->registerVerifiedUser();

        for ($i = 0; $i < 4; $i++) {
            $this->auth->attempt('jc@example.com', 'wrong password ' . $i, '10.0.0.1');
        }
        $this->assertTrue($this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1')->succeeded());

        for ($i = 0; $i < 4; $i++) {
            $this->auth->attempt('jc@example.com', 'wrong again ' . $i, '10.0.0.1');
        }
        $this->assertTrue($this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1')->succeeded());
    }

    public function testOneIpCannotSprayManyAccounts(): void
    {
        $this->registerVerifiedUser();

        for ($i = 0; $i < AuthService::MAX_ATTEMPTS_PER_IP; $i++) {
            $this->auth->attempt("user$i@example.com", 'guess guess guess', '10.0.0.9');
        }

        $result = $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.9');
        $this->assertSame(LoginStatus::Throttled, $result->status);
    }

    public function testOversizedPasswordsAreRejectedWithoutHashing(): void
    {
        $this->registerVerifiedUser();

        $result = $this->auth->attempt('jc@example.com', str_repeat('x', 5000), '10.0.0.1');

        $this->assertSame(LoginStatus::InvalidCredentials, $result->status);
    }

    public function testOutdatedHashesAreUpgradedOnLogin(): void
    {
        $now = $this->clock->now();
        $legacy = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 4]);
        $id = $this->users->create('old@example.com', 'Old Timer', $legacy, $now);
        $this->users->markVerified($id, $now);

        $this->assertTrue($this->auth->attempt('old@example.com', self::PASSWORD, '10.0.0.1')->succeeded());

        $hash = $this->users->findById($id)->passwordHash;
        $this->assertNotSame($legacy, $hash);
        $this->assertFalse($this->hasher->needsRehash($hash));
        $this->assertTrue((new PasswordHasher(['memory_cost' => 1024, 'time_cost' => 1]))->verify(self::PASSWORD, $hash));
    }

    public function testLogoutClearsTheSessionAndChangesTheId(): void
    {
        $this->registerVerifiedUser();
        $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1');
        $id = $this->session->id();

        $this->auth->logout();

        $this->assertNull($this->auth->user());
        $this->assertNotSame($id, $this->session->id());
        $this->assertNull($this->session->get('auth.user_id'));
    }

    public function testIdleSessionsExpire(): void
    {
        $this->registerVerifiedUser();
        $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1');

        $this->clock->advance(AuthService::IDLE_TIMEOUT - 10);
        $this->assertNotNull($this->auth->user(), 'Activity inside the window keeps the session alive.');

        $this->clock->advance(AuthService::IDLE_TIMEOUT + 1);
        $this->assertNull($this->auth->user());
    }

    public function testSessionsHaveAnAbsoluteLifetime(): void
    {
        $this->registerVerifiedUser();
        $this->auth->attempt('jc@example.com', self::PASSWORD, '10.0.0.1');

        // Stay active every 20 minutes; the session still ends at 12 hours.
        $elapsed = 0;
        while ($elapsed + 1200 <= AuthService::ABSOLUTE_TIMEOUT) {
            $this->clock->advance(1200);
            $elapsed += 1200;
            $this->assertNotNull($this->auth->user());
        }

        $this->clock->advance(1200);
        $this->assertNull($this->auth->user());
    }
}
