<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Auth\LoginThrottle;
use SecureAuth\Clock\FrozenClock;
use SecureAuth\Database\ConnectionFactory;

final class LoginThrottleTest extends TestCase
{
    private FrozenClock $clock;
    private LoginThrottle $throttle;
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = ConnectionFactory::create('sqlite::memory:');
        ConnectionFactory::loadSchema($this->pdo, dirname(__DIR__, 2) . '/database/schema.sql');

        $this->clock = new FrozenClock();
        $this->throttle = new LoginThrottle($this->pdo, $this->clock, 900);
    }

    public function testCountsAttemptsPerKey(): void
    {
        $a = LoginThrottle::key('login', 'a@example.com', '10.0.0.1');
        $b = LoginThrottle::key('login', 'b@example.com', '10.0.0.1');

        $this->throttle->hit($a);
        $this->throttle->hit($a);
        $this->throttle->hit($b);

        $this->assertSame(2, $this->throttle->attempts($a));
        $this->assertSame(1, $this->throttle->attempts($b));
    }

    public function testBlocksAtTheLimitUntilTheWindowPasses(): void
    {
        $key = LoginThrottle::key('login', 'a@example.com', '10.0.0.1');

        for ($i = 0; $i < 5; $i++) {
            $this->throttle->hit($key);
            $this->clock->advance(60);
        }

        $this->assertTrue($this->throttle->tooManyAttempts($key, 5));
        // First hit was 300s ago, so it drops out of the 900s window in 600s.
        $this->assertSame(600, $this->throttle->availableIn($key));

        $this->clock->advance(601);
        $this->assertFalse($this->throttle->tooManyAttempts($key, 5));
        $this->assertSame(4, $this->throttle->attempts($key));
    }

    public function testClearResetsTheCounter(): void
    {
        $key = LoginThrottle::key('x');
        $this->throttle->hit($key);
        $this->throttle->clear($key);

        $this->assertSame(0, $this->throttle->attempts($key));
        $this->assertSame(0, $this->throttle->availableIn($key));
    }

    public function testKeysAreHashedBeforeStorage(): void
    {
        $this->throttle->hit(LoginThrottle::key('login', 'secret@example.com', '192.168.1.5'));

        $stored = (string) $this->pdo->query('SELECT throttle_key FROM login_attempts')->fetchColumn();

        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $stored);
        $this->assertStringNotContainsString('secret', $stored);
    }

    public function testOldRowsArePruned(): void
    {
        $this->throttle->hit(LoginThrottle::key('old'));
        $this->clock->advance(1000);
        $this->throttle->hit(LoginThrottle::key('new'));

        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM login_attempts')->fetchColumn());
    }
}
