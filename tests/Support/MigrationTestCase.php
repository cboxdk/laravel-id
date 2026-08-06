<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support;

use Cbox\Id\Tests\TestCase;

/**
 * Base case for tests that drive the migrator themselves against a database of their
 * own ({@see ThrowawayDatabase}) and want the suite's connection left strictly alone.
 *
 * It exists to switch OFF {@see TestCase::defineDatabaseMigrations()}. On the default
 * path that helper hands the publishable users migration to Testbench's
 * MigrateProcessor, which migrates it up on the SUITE's connection and — this is the
 * part that bites — registers a `migrate:rollback --path=…` for teardown. Against
 * sqlite `:memory:` that is invisible, because the database dies with the connection.
 * Against a server engine it is not: measured on postgres:16, running a migration test
 * after the rest of the suite had migrated left the suite's `users` table DROPPED,
 * because the teardown rollback reversed the last batch that matched the path — a
 * batch this test never created.
 *
 * Nothing here needs the suite's schema, so the cleanest fix is to never touch it.
 */
abstract class MigrationTestCase extends TestCase
{
    protected function defineDatabaseMigrations(): void
    {
        // Intentionally empty — see the class docblock.
    }
}
