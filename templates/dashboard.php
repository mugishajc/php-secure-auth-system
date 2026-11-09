<h1>Hello, <?= e($user->name) ?></h1>
<p>You are signed in as <strong><?= e($user->email) ?></strong>.</p>
<p class="muted">Sessions end after 30 minutes of inactivity or 12 hours in total.</p>
<form method="post" action="/logout">
    <?= $csrfField ?>
    <button type="submit">Sign out</button>
</form>
