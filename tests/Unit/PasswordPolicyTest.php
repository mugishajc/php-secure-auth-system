<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Security\PasswordPolicy;

final class PasswordPolicyTest extends TestCase
{
    private PasswordPolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new PasswordPolicy();
    }

    public function testAcceptsALongPassphrase(): void
    {
        $this->assertSame([], $this->policy->check('blue kettle under the stairs'));
    }

    public function testRejectsShortPasswords(): void
    {
        $this->assertSame(['Password must be at least 12 characters.'], $this->policy->check('Sh0rt!pass'));
    }

    public function testCountsCharactersNotBytes(): void
    {
        // 12 characters, 24 bytes.
        $this->assertSame([], $this->policy->check('ééééééàààààç'));
    }

    public function testRejectsVeryLongPasswords(): void
    {
        $this->assertContains('Password must be at most 256 characters.', $this->policy->check(str_repeat('ab', 129)));
    }

    public function testRejectsCommonPasswordsCaseInsensitively(): void
    {
        $this->assertContains('This password is too common.', $this->policy->check('Password1234'));
    }

    public function testRejectsRepeatedCharacters(): void
    {
        $this->assertContains('Password must not be a single repeated character.', $this->policy->check(str_repeat('z', 20)));
    }

    public function testRejectsPasswordsContainingTheEmail(): void
    {
        $errors = $this->policy->check('my name is mugisha123', 'Mugisha@example.com');

        $this->assertContains('Password must not contain your email address.', $errors);
    }

    public function testShortEmailLocalPartsAreIgnored(): void
    {
        $this->assertSame([], $this->policy->check('a perfectly fine passphrase', 'jc@example.com'));
    }
}
