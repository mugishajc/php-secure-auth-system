<h1>Reset your password</h1>
<p>Enter your email and we'll send you a link to choose a new password.</p>
<form method="post" action="/forgot-password">
    <?= $csrfField ?>
    <label for="email">Email</label>
    <input id="email" type="email" name="email" autocomplete="email" required>
    <button type="submit">Send reset link</button>
</form>
<p><a href="/login">Back to sign in</a></p>
