<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Security\PasswordHasher;

final class PasswordHasherTest extends TestCase
{
    private PasswordHasher $hasher;

    protected function setUp(): void
    {
        // Low cost settings keep the suite fast; production uses the defaults.
        $this->hasher = new PasswordHasher(['memory_cost' => 1024, 'time_cost' => 1]);
    }

    public function testUsesArgon2id(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('PHP was built without Argon2 support.');
        }

        $this->assertSame(PASSWORD_ARGON2ID, $this->hasher->algorithm());
        $this->assertStringStartsWith('$argon2id$', $this->hasher->hash('correct horse battery staple'));
    }

    public function testVerifiesTheRightPasswordOnly(): void
    {
        $hash = $this->hasher->hash('correct horse battery staple');

        $this->assertTrue($this->hasher->verify('correct horse battery staple', $hash));
        $this->assertFalse($this->hasher->verify('correct horse battery stapler', $hash));
        $this->assertFalse($this->hasher->verify('', $hash));
    }

    public function testSaltsEachHash(): void
    {
        $this->assertNotSame(
            $this->hasher->hash('same password twice'),
            $this->hasher->hash('same password twice'),
        );
    }

    public function testFlagsOldAlgorithmsAndCostsForRehash(): void
    {
        $bcrypt = password_hash('legacy password', PASSWORD_BCRYPT, ['cost' => 4]);
        $this->assertTrue($this->hasher->needsRehash($bcrypt));

        $current = $this->hasher->hash('fresh password');
        $this->assertFalse($this->hasher->needsRehash($current));

        $stronger = new PasswordHasher(['memory_cost' => 2048, 'time_cost' => 2]);
        $this->assertTrue($stronger->needsRehash($current));
    }
}
