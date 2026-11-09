<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecureAuth\Auth\User;
use SecureAuth\Web\View;

final class EscapeTest extends TestCase
{
    public function testEscapesHtmlSpecialCharacters(): void
    {
        $this->assertSame(
            '&lt;a href=&quot;x&quot;&gt;&apos;&amp;&lt;/a&gt;',
            e('<a href="x">\'&</a>'),
        );
    }

    public function testHandlesNullAndNumbers(): void
    {
        $this->assertSame('', e(null));
        $this->assertSame('42', e(42));
    }

    public function testReplacesInvalidUtf8(): void
    {
        $this->assertSame("a\u{FFFD}b", e("a\xFFb"));
    }

    public function testTemplatesEscapeUserControlledValues(): void
    {
        $user = new User(1, 'x@example.com', '<script>alert(1)</script>', 'hash', 1, 1);
        $view = new View(dirname(__DIR__, 2) . '/templates');

        $html = $view->render('dashboard', ['user' => $user, 'csrfField' => '', 'title' => '"><b>']);

        $this->assertStringContainsString('Hello, &lt;script&gt;alert(1)&lt;/script&gt;', $html);
        $this->assertStringNotContainsString('<script>alert(1)', $html);
        $this->assertStringContainsString('<title>&quot;&gt;&lt;b&gt;</title>', $html);
    }
}
