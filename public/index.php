<?php

declare(strict_types=1);

use SecureAuth\Auth\AuthService;
use SecureAuth\Auth\LoginStatus;
use SecureAuth\Auth\LoginThrottle;
use SecureAuth\Auth\TokenRepository;
use SecureAuth\Auth\UserRepository;
use SecureAuth\Auth\ValidationException;
use SecureAuth\Clock\SystemClock;
use SecureAuth\Database\ConnectionFactory;
use SecureAuth\Mail\LogMailer;
use SecureAuth\Security\Csrf;
use SecureAuth\Security\PasswordHasher;
use SecureAuth\Session\NativeSessionStore;
use SecureAuth\Web\SecurityHeaders;
use SecureAuth\Web\View;

require dirname(__DIR__) . '/vendor/autoload.php';

$config = require dirname(__DIR__) . '/config.php';

// Wiring

$pdo = ConnectionFactory::create($config['db_dsn']);
$clock = new SystemClock();
$session = new NativeSessionStore($config['session_secure']);
$session->start();

$auth = new AuthService(
    new UserRepository($pdo),
    new TokenRepository($pdo),
    new PasswordHasher(),
    new LoginThrottle($pdo, $clock),
    $session,
    new LogMailer($config['mail_log']),
    $clock,
    $config['app_url'],
);
$csrf = new Csrf($session);
$view = new View(dirname(__DIR__) . '/templates');

SecurityHeaders::send($config['session_secure']);

// Helpers

/** Reads a string field; arrays and other types become an empty string. */
$field = static fn (array $source, string $key): string => is_string($source[$key] ?? null) ? $source[$key] : '';

$page = static function (string $template, array $data = [], int $status = 200) use ($view, $csrf, $session): never {
    $flash = $session->get('_flash');
    $session->remove('_flash');

    http_response_code($status);
    echo $view->render($template, $data + [
        'csrfField' => $csrf->field(),
        'flash' => is_string($flash) ? $flash : null,
    ]);
    exit;
};

$redirect = static function (string $to, ?string $flash = null) use ($session): never {
    if ($flash !== null) {
        $session->set('_flash', $flash);
    }
    header('Location: ' . $to, true, 303);
    exit;
};

// Routing

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = '/' . trim((string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH), '/');
$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

if ($method === 'POST' && !$csrf->validate($_POST['_csrf'] ?? null)) {
    $page('message', [
        'heading' => 'Session expired',
        'message' => 'The form was missing a valid security token. Go back, reload the page and try again.',
    ], 419);
}

switch ("$method $path") {
    case 'GET /':
        $user = $auth->user();
        if ($user === null) {
            $redirect('/login');
        }
        $page('dashboard', ['user' => $user, 'title' => 'Dashboard']);

    case 'GET /register':
        $page('register', ['title' => 'Create an account']);

    case 'POST /register':
        try {
            $auth->register($field($_POST, 'email'), $field($_POST, 'name'), $field($_POST, 'password'));
        } catch (ValidationException $e) {
            // Never echo the password back into the form.
            $page('register', [
                'errors' => $e->errors,
                'old' => ['email' => $field($_POST, 'email'), 'name' => $field($_POST, 'name')],
            ], 422);
        }
        $redirect('/login', 'Check your inbox for a link to confirm your email address.');

    case 'GET /login':
        if ($auth->check()) {
            $redirect('/');
        }
        $page('login', ['title' => 'Sign in']);

    case 'POST /login':
        $result = $auth->attempt($field($_POST, 'email'), $field($_POST, 'password'), $ip);

        if ($result->succeeded()) {
            $csrf->rotate();
            $redirect('/');
        }

        if ($result->status === LoginStatus::Throttled) {
            header('Retry-After: ' . $result->retryAfter);
        }

        $page('login', [
            'error' => $result->message(),
            'email' => $field($_POST, 'email'),
        ], $result->status === LoginStatus::Throttled ? 429 : 401);

    case 'POST /logout':
        $auth->logout();
        $csrf->rotate();
        $redirect('/login', 'You have been signed out.');

    case 'GET /verify-email':
        $redirect('/login', $auth->verifyEmail($field($_GET, 'token'))
            ? 'Email confirmed. You can sign in now.'
            : 'That confirmation link is invalid or has expired.');

    case 'GET /forgot-password':
        $page('forgot-password', ['title' => 'Reset your password']);

    case 'POST /forgot-password':
        $auth->requestPasswordReset($field($_POST, 'email'), $ip);
        // Same answer whether or not the account exists.
        $redirect('/login', 'If an account exists for that email, a reset link is on its way.');

    case 'GET /reset-password':
        $token = $field($_GET, 'token');
        if (!$auth->isValidResetToken($token)) {
            $page('message', [
                'heading' => 'Link expired',
                'message' => 'That reset link is invalid or has expired. Request a new one.',
            ], 410);
        }
        $page('reset-password', ['token' => $token, 'title' => 'Choose a new password']);

    case 'POST /reset-password':
        $token = $field($_POST, 'token');
        try {
            $changed = $auth->resetPassword($token, $field($_POST, 'password'));
        } catch (ValidationException $e) {
            $page('reset-password', ['token' => $token, 'errors' => $e->errors], 422);
        }
        $changed
            ? $redirect('/login', 'Password changed. Sign in with your new password.')
            : $redirect('/forgot-password', 'That reset link is invalid or has expired.');

    default:
        $page('message', ['heading' => 'Not found', 'message' => 'There is nothing at this address.'], 404);
}
