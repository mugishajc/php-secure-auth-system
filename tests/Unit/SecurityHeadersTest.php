<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Web\SecurityHeaders;

final class SecurityHeadersTest extends TestCase
{
    public function testSetsProtectiveHeaders(): void
    {
        $headers = SecurityHeaders::all(false);

        $this->assertSame('no-referrer', $headers['Referrer-Policy']);
        $this->assertSame('DENY', $headers['X-Frame-Options']);
        $this->assertSame('no-store', $headers['Cache-Control']);
        $this->assertStringContainsString("frame-ancestors 'none'", $headers['Content-Security-Policy']);
        $this->assertArrayNotHasKey('Strict-Transport-Security', $headers);
    }

    public function testAddsHstsOverHttps(): void
    {
        $this->assertArrayHasKey('Strict-Transport-Security', SecurityHeaders::all(true));
    }
}
