<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Security\Csrf;
use SecureAuth\Session\ArraySessionStore;

final class CsrfTest extends TestCase
{
    public function testTokenIsStableUntilRotated(): void
    {
        $csrf = new Csrf(new ArraySessionStore());
        $token = $csrf->token();

        $this->assertSame($token, $csrf->token());
        $this->assertNotSame($token, $csrf->rotate());
    }

    public function testValidatesOnlyTheCurrentToken(): void
    {
        $csrf = new Csrf(new ArraySessionStore());
        $old = $csrf->token();

        $this->assertTrue($csrf->validate($old));
        $this->assertFalse($csrf->validate(strrev($old)));
        $this->assertFalse($csrf->validate(''));
        $this->assertFalse($csrf->validate(null));
        $this->assertFalse($csrf->validate([$old]));

        $csrf->rotate();
        $this->assertFalse($csrf->validate($old));
    }

    public function testTokensAreBoundToTheSession(): void
    {
        $mine = new Csrf(new ArraySessionStore());
        $theirs = new Csrf(new ArraySessionStore());

        $this->assertFalse($mine->validate($theirs->token()));
    }

    public function testHiddenFieldContainsTheToken(): void
    {
        $csrf = new Csrf(new ArraySessionStore());

        $this->assertSame(
            '<input type="hidden" name="_csrf" value="' . $csrf->token() . '">',
            $csrf->field(),
        );
    }
}
