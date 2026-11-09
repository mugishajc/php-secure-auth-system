<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title ?? 'Secure Auth') ?></title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<main class="card">
    <?php if (!empty($flash)): ?>
        <p class="notice" role="status"><?= e($flash) ?></p>
    <?php endif; ?>
    <?= $content /* already escaped by the page template */ ?>
</main>
</body>
</html>
