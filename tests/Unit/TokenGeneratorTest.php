<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Security\TokenGenerator;

final class TokenGeneratorTest extends TestCase
{
    public function testTokensAre256BitHexStrings(): void
    {
        $token = (new TokenGenerator())->generate();

        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $token);
    }

    public function testTokensDoNotRepeat(): void
    {
        $generator = new TokenGenerator();
        $tokens = array_map(static fn () => $generator->generate(), range(1, 200));

        $this->assertCount(200, array_unique($tokens));
    }

    public function testHashIsDeterministicAndDifferentFromTheToken(): void
    {
        $generator = new TokenGenerator();
        $token = $generator->generate();

        $this->assertSame($generator->hash($token), $generator->hash($token));
        $this->assertNotSame($token, $generator->hash($token));
        $this->assertSame(hash('sha256', $token), $generator->hash($token));
    }
}
