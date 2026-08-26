<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\ClientRegistryService;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * REPAIRS `legacy_login_declarations.client_id` ON AN INSTALL THAT ALREADY RAN THE CREATE.
 *
 * The create migration declared it `string('client_id', 26)` — the ULID width, taken from
 * the three genuine ULID columns above it in the same table. A client id is not one of
 * those: {@see ClientRegistryService} mints `'cid_'.Str::ulid()`, so
 * every value the column will ever hold is THIRTY characters, four more than it could take.
 *
 * Per engine:
 *
 *  - PostgreSQL refuses the insert — `SQLSTATE[22001] value too long for type character
 *    varying(26)`. Declaring a legacy login is impossible.
 *  - MySQL in strict mode refuses it too; without strict mode it TRUNCATES the id to
 *    `cid_01m0zcf84c14s7ng7tzhj7h`, which matches no client, so the console can never name
 *    the app that proposed the URL.
 *  - SQLite ignores declared widths entirely, which is why the suite was green and why the
 *    engine matrix did not catch it either: the one test that writes this row used
 *    `'client-a'` as the client id, a fixture eight characters long and shaped like nothing
 *    this column ever holds.
 *
 * The create migration is fixed as well, so a fresh install never has the narrow column.
 * Both state a WIDTH rather than a delta, so an install that runs the corrected create and
 * then this is unaffected by running both.
 *
 * NO BACKFILL, and none is possible: on the engines where the column is wrong no row was
 * ever written, and on SQLite the value went in whole regardless of the declaration.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Nothing to widen on an install that predates the feature.
        if (! Schema::hasTable('legacy_login_declarations')) {
            return;
        }

        Schema::table('legacy_login_declarations', function (Blueprint $table): void {
            /*
             * NO `->index()`, even though the column has one. `change()` APPLIES the
             * modifiers it is given rather than preserving what is there — spelling the
             * index here asks PostgreSQL to create one it already has, and the migration
             * dies on a duplicate relation instead of widening anything. The existing index
             * survives a type change on its own.
             */
            $table->string('client_id')->change();
        });
    }

    public function down(): void
    {
        /*
         * NOT REVERSED. The previous width could not hold a single valid client id, so
         * narrowing back would refuse or truncate every row written since — and there is no
         * state worth returning to. `MigrationRollbackTest` allows a deliberate no-op down;
         * what it forbids is a down that leaves the schema half-reverted.
         */
    }
};
