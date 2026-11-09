<h1>Choose a new password</h1>
<?php require __DIR__ . '/errors.php'; ?>
<form method="post" action="/reset-password">
    <?= $csrfField ?>
    <input type="hidden" name="token" value="<?= e($token) ?>">
    <label for="password">New password</label>
    <input id="password" type="password" name="password" minlength="12" maxlength="256" autocomplete="new-password" required>
    <button type="submit">Save password</button>
</form>
