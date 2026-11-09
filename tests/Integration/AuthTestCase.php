<?php

declare(strict_types=1);

namespace Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;
use SecureAuth\Auth\AuthService;
use SecureAuth\Auth\LoginThrottle;
use SecureAuth\Auth\TokenRepository;
use SecureAuth\Auth\UserRepository;
use SecureAuth\Clock\FrozenClock;
use SecureAuth\Database\ConnectionFactory;
use SecureAuth\Mail\InMemoryMailer;
use SecureAuth\Security\PasswordHasher;
use SecureAuth\Session\ArraySessionStore;
use SecureAuth\Session\SessionStore;

/**
 * Wires the real services together on an in-memory SQLite database with
 * a frozen clock, an in-memory mailer and array sessions.
 */
abstract class AuthTestCase extends TestCase
{
    protected const PASSWORD = 'blue kettle under the stairs';

    protected PDO $pdo;
    protected FrozenClock $clock;
    protected InMemoryMailer $mailer;
    protected PasswordHasher $hasher;
    protected UserRepository $users;
    protected ArraySessionStore $session;
    protected AuthService $auth;

    protected function setUp(): void
    {
        $this->pdo = ConnectionFactory::create('sqlite::memory:');
        ConnectionFactory::loadSchema($this->pdo, dirname(__DIR__, 2) . '/database/schema.sql');

        $this->clock = new FrozenClock();
        $this->mailer = new InMemoryMailer();
        $this->hasher = new PasswordHasher(['memory_cost' => 1024, 'time_cost' => 1]);
        $this->users = new UserRepository($this->pdo);
        $this->session = new ArraySessionStore();
        $this->auth = $this->makeAuth($this->session);
    }

    /**
     * A second AuthService sharing the database, as if from another browser.
     */
    protected function makeAuth(SessionStore $session): AuthService
    {
        return new AuthService(
            $this->users,
            new TokenRepository($this->pdo),
            $this->hasher,
            new LoginThrottle($this->pdo, $this->clock),
            $session,
            $this->mailer,
            $this->clock,
            'https://auth.test',
        );
    }

    /**
     * Pulls the token out of the most recent email's link.
     */
    protected function tokenFromLastMail(): string
    {
        $mail = $this->mailer->last();
        $this->assertNotNull($mail, 'No email was sent.');
        $this->assertSame(1, preg_match('/token=([a-f0-9]{64})/', $mail['body'], $m), 'No token link in the email.');

        return $m[1];
    }

    protected function registerVerifiedUser(string $email = 'jc@example.com'): void
    {
        $this->auth->register($email, 'Jean Claude', self::PASSWORD);
        $this->assertTrue($this->auth->verifyEmail($this->tokenFromLastMail()));
    }
}
