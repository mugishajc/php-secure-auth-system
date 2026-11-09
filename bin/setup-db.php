<?php

declare(strict_types=1);

use SecureAuth\Database\ConnectionFactory;

require dirname(__DIR__) . '/vendor/autoload.php';

$config = require dirname(__DIR__) . '/config.php';

$pdo = ConnectionFactory::create($config['db_dsn']);
ConnectionFactory::loadSchema($pdo, dirname(__DIR__) . '/database/schema.sql');

echo "Database ready: {$config['db_dsn']}\n";
