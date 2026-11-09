# PHP secure auth system

An authentication module in plain PHP 8.2 that gets the security details right:
password storage, login throttling, session handling, CSRF, email verification and
password reset. A small demo site sits on top so you can click through the flows.

![CI](https://github.com/mugishajc/php-secure-auth-system/actions/workflows/ci.yml/badge.svg)

## What it does

| Concern | How it's handled | Where |
| --- | --- | --- |
| Password storage | `password_hash` with Argon2id (64 MiB, t=4), bcrypt only if PHP lacks Argon2. Old hashes are upgraded on the next login | `src/Security/PasswordHasher.php` |
| Password rules | 12 to 256 characters, common-password block list, no single repeated character, must not contain the email name. No composition rules (NIST 800-63B style) | `src/Security/PasswordPolicy.php` |
| Login throttling | 5 failures per email+IP and 50 per IP in a sliding 15 minute window, stored in the database with hashed keys | `src/Auth/LoginThrottle.php` |
| User enumeration | Same message and similar timing for unknown email and wrong password (a dummy hash is verified). Sign-up and reset forms answer the same way whether or not the account exists | `src/Auth/AuthService.php` |
| Session fixation | `session_regenerate_id(true)` on login, full invalidation on logout | `src/Session/NativeSessionStore.php` |
| Session cookies | `HttpOnly`, `SameSite=Lax`, `Secure` and the `__Host-` prefix over HTTPS, strict mode, cookies only | `src/Session/NativeSessionStore.php` |
| Session lifetime | 30 minute idle timeout, 12 hour absolute timeout | `AuthService::user()` |
| Password change | Bumps `session_version`, which signs out every other session | `UserRepository::changePassword()` |
| CSRF | Per-session token checked with `hash_equals` on every POST, rotated on login and logout | `src/Security/Csrf.php` |
| Email tokens | 256-bit random tokens. Only the SHA-256 hash is stored. Verification links last 24 hours, reset links 1 hour, both single use. Only the newest reset link works | `src/Auth/TokenRepository.php` |
| Reset abuse | At most 3 reset emails per address per window | `AuthService::requestPasswordReset()` |
| SQL injection | PDO with real prepared statements (`ATTR_EMULATE_PREPARES = false`) and bound parameters everywhere | `src/Auth/*Repository.php` |
| XSS | Every value in the templates goes through `e()` (`htmlspecialchars` with `ENT_QUOTES`, `ENT_SUBSTITUTE`) | `src/helpers.php`, `templates/` |
| Headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` (reset tokens live in URLs), `Cache-Control: no-store`, HSTS over HTTPS | `src/Web/SecurityHeaders.php` |

## Requirements

- PHP 8.2+ with `pdo_sqlite` and `mbstring` (Argon2 support recommended)
- Composer

## Running the demo

```bash
composer install
cp .env.example .env
php bin/setup-db.php
php -S localhost:8000 -t public
```

Open http://localhost:8000/register. Emails are not sent; they are appended to
`storage/mail.log`, so open the verification or reset link from there.

Set `SESSION_SECURE=1` when serving over HTTPS. That turns on the `Secure` cookie flag,
the `__Host-` cookie name and HSTS.

## Pages

| Method | Path | Purpose |
| --- | --- | --- |
| GET, POST | `/register` | Create an account, sends a verification email |
| GET | `/verify-email?token=...` | Confirm the email address |
| GET, POST | `/login` | Sign in (401 on bad credentials, 429 with `Retry-After` when throttled) |
| POST | `/logout` | Sign out |
| GET, POST | `/forgot-password` | Request a reset link |
| GET, POST | `/reset-password?token=...` | Choose a new password |
| GET | `/` | Dashboard for the signed-in user |

## Using the module in your own code

```php
$auth = new AuthService(
    new UserRepository($pdo),
    new TokenRepository($pdo),
    new PasswordHasher(),
    new LoginThrottle($pdo, $clock),
    $session,          // NativeSessionStore in production
    $mailer,           // implement SecureAuth\Mail\Mailer
    $clock,
    'https://example.com',
);

$result = $auth->attempt($email, $password, $_SERVER['REMOTE_ADDR']);

if ($result->succeeded()) {
    $csrf->rotate();
    // redirect
} else {
    echo e($result->message());
}
```

`AuthService` does not touch superglobals. The session, mailer and clock are
interfaces, which is what makes the timeouts and expiry rules testable.

## Tests

```bash
vendor/bin/phpunit
```

- `tests/Unit`: hasher, password policy, tokens, CSRF, escaping, throttle, headers
- `tests/Integration`: registration, verification, login, throttling, session
  fixation, idle and absolute timeouts, rehashing, password reset, signing out other
  sessions. These use in-memory SQLite and a frozen clock.

CI also starts the built-in server and runs `bin/smoke-test.sh`, which signs up,
confirms the email from the mail log, signs in, and checks the cookie flags, the
headers and CSRF rejection with curl.

## Things I left out on purpose

- Two-factor authentication
- Remember-me cookies
- A real mail transport (plug in any `Mailer`)
- Trusting `X-Forwarded-For`. Behind a proxy, pass the real client IP into
  `attempt()` yourself, or the per-IP limit will treat every user as one client.

## License

MIT
