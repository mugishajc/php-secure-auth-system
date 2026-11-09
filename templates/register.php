<h1>Create an account</h1>
<?php require __DIR__ . '/errors.php'; ?>
<form method="post" action="/register">
    <?= $csrfField ?>
    <label for="name">Name</label>
    <input id="name" name="name" value="<?= e($old['name'] ?? '') ?>" maxlength="100" autocomplete="name" required>
    <label for="email">Email</label>
    <input id="email" type="email" name="email" value="<?= e($old['email'] ?? '') ?>" autocomplete="email" required>
    <label for="password">Password <small>(at least 12 characters)</small></label>
    <input id="password" type="password" name="password" minlength="12" maxlength="256" autocomplete="new-password" required>
    <button type="submit">Create account</button>
</form>
<p>Already registered? <a href="/login">Sign in</a></p>
