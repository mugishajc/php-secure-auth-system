<?php if (!empty($errors)): ?>
    <ul class="errors" role="alert">
        <?php foreach ($errors as $messages): ?>
            <?php foreach ($messages as $message): ?>
                <li><?= e($message) ?></li>
            <?php endforeach; ?>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>
