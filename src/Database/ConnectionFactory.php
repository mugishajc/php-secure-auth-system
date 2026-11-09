<?php

declare(strict_types=1);

namespace SecureAuth\Database;

use PDO;
use RuntimeException;

final class ConnectionFactory
{
    public static function create(string $dsn, ?string $username = null, ?string $password = null): PDO
    {
        $pdo = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Use real server-side prepared statements where the driver supports them.
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $pdo->exec('PRAGMA foreign_keys = ON');
        }

        return $pdo;
    }

    /**
     * Runs every statement in a schema file. Statements are separated by
     * semicolons, so the file must not contain semicolons inside strings.
     */
    public static function loadSchema(PDO $pdo, string $file): void
    {
        $sql = file_get_contents($file);
        if ($sql === false) {
            throw new RuntimeException("Cannot read schema file $file");
        }

        // Drop comment lines before splitting.
        $sql = preg_replace('/^\s*--.*$/m', '', $sql) ?? $sql;

        foreach (array_filter(array_map('trim', explode(';', $sql))) as $statement) {
            $pdo->exec($statement);
        }
    }
}
