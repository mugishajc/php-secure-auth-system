<h1>Sign in</h1>
<?php if (!empty($error)): ?>
    <p class="error" role="alert"><?= e($error) ?></p>
<?php endif; ?>
<form method="post" action="/login">
    <?= $csrfField ?>
    <label for="email">Email</label>
    <input id="email" type="email" name="email" value="<?= e($email ?? '') ?>" autocomplete="username" required>
    <label for="password">Password</label>
    <input id="password" type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
</form>
<p><a href="/forgot-password">Forgot your password?</a> &middot; <a href="/register">Create an account</a></p>
