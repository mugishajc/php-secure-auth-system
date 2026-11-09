<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

use SecureAuth\Clock\Clock;
use SecureAuth\Mail\Mailer;
use SecureAuth\Security\PasswordHasher;
use SecureAuth\Security\PasswordPolicy;
use SecureAuth\Security\TokenGenerator;
use SecureAuth\Session\SessionStore;

final class AuthService
{
    public const MAX_ATTEMPTS_PER_ACCOUNT = 5;
    public const MAX_ATTEMPTS_PER_IP = 50;

    public const VERIFY_TOKEN_TTL = 86_400;     // 24 hours
    public const RESET_TOKEN_TTL = 3_600;       // 1 hour
    public const IDLE_TIMEOUT = 1_800;          // 30 minutes
    public const ABSOLUTE_TIMEOUT = 43_200;     // 12 hours

    private const SESSION_USER = 'auth.user_id';
    private const SESSION_VERSION = 'auth.version';
    private const SESSION_STARTED = 'auth.started_at';
    private const SESSION_SEEN = 'auth.last_seen_at';

    private ?string $dummyHash = null;

    public function __construct(
        private UserRepository $users,
        private TokenRepository $tokens,
        private PasswordHasher $hasher,
        private LoginThrottle $throttle,
        private SessionStore $session,
        private Mailer $mailer,
        private Clock $clock,
        private string $appUrl,
        private TokenGenerator $tokenGenerator = new TokenGenerator(),
        private PasswordPolicy $policy = new PasswordPolicy(),
    ) {
    }

    public static function normalizeEmail(string $email): string
    {
        return mb_strtolower(trim($email));
    }

    /**
     * Creates an unverified account and emails a verification link.
     *
     * If the email is already registered nothing is created, but the owner
     * gets a notice instead. The caller sees the same outcome either way,
     * so the form can't be used to find out who has an account.
     *
     * @throws ValidationException
     */
    public function register(string $email, string $name, string $password): void
    {
        $email = self::normalizeEmail($email);
        $name = trim($name);

        $errors = [];
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 254) {
            $errors['email'][] = 'Enter a valid email address.';
        }
        if ($name === '' || mb_strlen($name) > 100) {
            $errors['name'][] = 'Name is required and must be at most 100 characters.';
        }
        foreach ($this->policy->check($password, $email) as $problem) {
            $errors['password'][] = $problem;
        }
        if ($errors !== []) {
            throw new ValidationException($errors);
        }

        $existing = $this->users->findByEmail($email);
        if ($existing !== null) {
            $this->mailer->send(
                $email,
                'Sign-up attempt for your account',
                "Someone tried to create an account with this email address.\n"
                . "If it was you, you can sign in or reset your password at {$this->appUrl}/forgot-password.\n"
                . "If not, you can ignore this message.",
            );

            return;
        }

        $now = $this->clock->now();
        $userId = $this->users->create($email, $name, $this->hasher->hash($password), $now);

        $this->sendVerificationEmail($userId, $email);
    }

    public function sendVerificationEmail(int $userId, string $email): void
    {
        $token = $this->issueToken($userId, TokenRepository::VERIFY_EMAIL, self::VERIFY_TOKEN_TTL);

        $this->mailer->send(
            $email,
            'Confirm your email address',
            "Open this link to confirm your email address:\n\n"
            . "{$this->appUrl}/verify-email?token={$token}\n\n"
            . 'The link expires in 24 hours.',
        );
    }

    public function verifyEmail(string $token): bool
    {
        $row = $this->tokens->findValid(TokenRepository::VERIFY_EMAIL, $this->tokenGenerator->hash($token), $this->clock->now());
        if ($row === null || !$this->tokens->consume($row['id'], $this->clock->now())) {
            return false;
        }

        $this->users->markVerified($row['user_id'], $this->clock->now());

        return true;
    }

    public function attempt(string $email, string $password, string $ip): LoginResult
    {
        $email = self::normalizeEmail($email);
        $accountKey = LoginThrottle::key('login', $email, $ip);
        $ipKey = LoginThrottle::key('login-ip', $ip);

        if ($this->throttle->tooManyAttempts($accountKey, self::MAX_ATTEMPTS_PER_ACCOUNT)) {
            return LoginResult::throttled($this->throttle->availableIn($accountKey));
        }
        if ($this->throttle->tooManyAttempts($ipKey, self::MAX_ATTEMPTS_PER_IP)) {
            return LoginResult::throttled($this->throttle->availableIn($ipKey));
        }

        $user = $this->users->findByEmail($email);

        // Verify against a dummy hash when the user doesn't exist, so the
        // response time doesn't reveal which emails are registered.
        $valid = $this->hasher->verify($password, $user?->passwordHash ?? $this->dummyHash());

        if ($user === null || !$valid) {
            $this->throttle->hit($accountKey);
            $this->throttle->hit($ipKey);

            return LoginResult::invalid();
        }

        if (!$user->isVerified()) {
            return LoginResult::unverified();
        }

        if ($this->hasher->needsRehash($user->passwordHash)) {
            $this->users->updateHash($user->id, $this->hasher->hash($password), $this->clock->now());
        }

        $this->throttle->clear($accountKey);
        $this->startAuthenticatedSession($user);

        return LoginResult::success($user);
    }

    /**
     * The signed-in user, or null. Enforces idle and absolute timeouts and
     * drops sessions opened before the last password change.
     */
    public function user(): ?User
    {
        $id = $this->session->get(self::SESSION_USER);
        if (!is_int($id)) {
            return null;
        }

        $now = $this->clock->now();
        $started = (int) $this->session->get(self::SESSION_STARTED, 0);
        $seen = (int) $this->session->get(self::SESSION_SEEN, 0);

        if ($now - $seen > self::IDLE_TIMEOUT || $now - $started > self::ABSOLUTE_TIMEOUT) {
            $this->logout();

            return null;
        }

        $user = $this->users->findById($id);
        if ($user === null || $user->sessionVersion !== $this->session->get(self::SESSION_VERSION)) {
            $this->logout();

            return null;
        }

        $this->session->set(self::SESSION_SEEN, $now);

        return $user;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function logout(): void
    {
        $this->session->invalidate();
    }

    private function startAuthenticatedSession(User $user): void
    {
        // New id on every privilege change: an id planted before login
        // (session fixation) is useless afterwards.
        $this->session->regenerate();

        $now = $this->clock->now();
        $this->session->set(self::SESSION_USER, $user->id);
        $this->session->set(self::SESSION_VERSION, $user->sessionVersion);
        $this->session->set(self::SESSION_STARTED, $now);
        $this->session->set(self::SESSION_SEEN, $now);
    }

    private function issueToken(int $userId, string $type, int $ttl): string
    {
        $now = $this->clock->now();
        $token = $this->tokenGenerator->generate();

        $this->tokens->create($userId, $type, $this->tokenGenerator->hash($token), $now + $ttl, $now);

        return $token;
    }

    private function dummyHash(): string
    {
        return $this->dummyHash ??= $this->hasher->hash(bin2hex(random_bytes(16)));
    }
}
