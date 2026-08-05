<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Make `projects.account_id` optional, so an ORGANIZATION can own a project alone.
 *
 * This is the subtractive half `2026_08_06_000100` deliberately left out. That migration
 * added `organization_id`, backfilled it from every homed account, and said in as many
 * words that dropping the account requirement was a separate step. This is that step.
 *
 * WHY IT IS NOT COSMETIC. `account_id` is NOT NULL *and* carries a cascade to `accounts`.
 * While both hold, an organization cannot own a project without an account row standing
 * behind it, and the account plane is the thing being folded away — so this column is the
 * constraint that would make folding it impossible, not a leftover from it. Nothing writes
 * a project without an account yet; this is what makes writing one possible.
 *
 * THE CASCADE STAYS, and that is deliberate. It still expresses something true today: a
 * project whose account is deleted has no owner on the account plane and should go with
 * it. Dropping the foreign key belongs with dropping `accounts` itself, in one migration
 * where both halves are visible — because a DROP TABLE with this cascade still live would
 * take every project with it, and that is a fact about the DROP, not about this column's
 * nullability. Splitting the two would leave a window in which the guard is gone and the
 * table it guards is still there.
 *
 * NO ROW IS REWRITTEN. Every existing project keeps its `account_id`; the column merely
 * stops requiring one. A reader that has always used `forAccount()` sees no change, and
 * `Project::booted()` still derives the organization from the account when one is given.
 *
 * ENGINE NOTES. `change()` is Laravel's native column alteration — no doctrine/dbal.
 *
 *  - MySQL rewrites the column definition in place. A `MODIFY` that omitted the foreign
 *    key would not drop it (the key is a separate object), but it DOES need the full type
 *    restated, which `string('account_id', 26)->nullable()->change()` supplies.
 *  - PostgreSQL issues `ALTER COLUMN ... DROP NOT NULL`, which takes no table rewrite and
 *    no long lock.
 *  - SQLite rebuilds the table. That is why the guard below runs FIRST and outside the
 *    schema call: SQLite's rebuild re-validates every index and foreign key against the
 *    new definition, and an assertion issued afterwards would be asserting against a
 *    table it had just recreated rather than against the one that existed.
 */
return new class extends Migration
{
    public function up(): void
    {
        // A project with no organization would become a project with no owner at all the
        // moment its account is allowed to be absent — the account is what its
        // organization was derived FROM. `2026_08_06_000100` backfilled every homed
        // account's projects, so the only rows this can find are projects of an account
        // that was itself never homed, which `2026_08_05_000200` was supposed to have
        // homed first.
        //
        // Repaired rather than refused. Refusing would leave a deployment unable to
        // migrate with no action it could take that this could not take for it, and the
        // source is right there: the account row. A project whose account has no
        // organization either is left alone and reported — there is nothing to derive
        // from, and inventing an organization is worse than a row an operator can see.
        DB::table('projects')
            ->whereNull('organization_id')
            ->orderBy('id')
            ->cursor()
            ->each(function (object $project): void {
                $accountId = $project->account_id ?? null;

                if (! is_string($accountId) || $accountId === '') {
                    return;
                }

                $organizationId = DB::table('accounts')->where('id', $accountId)->value('organization_id');

                if (! is_string($organizationId) || $organizationId === '') {
                    return;
                }

                DB::table('projects')
                    ->where('id', $project->id)
                    ->whereNull('organization_id')
                    ->update(['organization_id' => $organizationId]);
            });

        $orphans = DB::table('projects')->whereNull('organization_id')->count();

        if ($orphans > 0) {
            // Not an exception. The column is about to become nullable, which takes
            // nothing away from these rows — they are already owned by an account and go
            // on being owned by it. But they will not survive the account plane being
            // folded away, and the only moment anybody is looking at this is now.
            report(new RuntimeException(
                "{$orphans} project(s) have no organization and no homed account behind them. "
                .'They will lose their owner when the account plane is retired; home their '
                .'accounts (see 2026_08_05_000200) before that migration runs.'
            ));
        }

        if (! $this->accountIsRequired()) {
            return;
        }

        // FOREIGN KEYS OFF FOR THE ALTERATION, and SQLite is why. Laravel implements a
        // column change there by building a new table, copying the rows and dropping the
        // old one — and `environments.project_id` references `projects`, so the DROP is
        // refused outright: `FOREIGN KEY constraint failed (SQL: drop table "projects")`.
        // The rebuild is invisible in the migration's text, which is exactly how this
        // would have reached a deployment: it passes review, and it fails on the engine.
        //
        // Nothing here can orphan a row. The only change is that a column stops requiring
        // a value; no row is written, no row is deleted, and every foreign key is
        // re-validated when the checks come back on. On MySQL and PostgreSQL there is no
        // rebuild at all and this costs nothing.
        Schema::withoutForeignKeyConstraints(function (): void {
            Schema::table('projects', function (Blueprint $table): void {
                $table->string('account_id', 26)->nullable()->change();
            });
        });
    }

    /**
     * Whether `projects.account_id` still demands a value.
     *
     * Asked so the alteration is skipped when it has already happened, which makes the
     * whole migration re-runnable — the data repair above already is, by `whereNull`, and
     * a migration that repairs idempotently and then unconditionally rebuilds a table is
     * only half safe to re-run.
     *
     * It is also the only way to exercise the repair from a test. SQLite implements a
     * column change by building a new table and dropping the old one, `environments`
     * references `projects`, and `PRAGMA foreign_keys` cannot be changed inside a
     * transaction — so under `RefreshDatabase` the DROP is refused no matter what
     * `withoutForeignKeyConstraints()` asks for. Outside a transaction, where migrations
     * actually run, it is fine; the wrapper stays for that path.
     */
    private function accountIsRequired(): bool
    {
        foreach (Schema::getColumns('projects') as $column) {
            if ($column['name'] === 'account_id') {
                return $column['nullable'] === false;
            }
        }

        return false;
    }

    /**
     * Restoring NOT NULL can fail, and honestly so.
     *
     * By the time anybody rolls this back there may be projects an organization owns with
     * no account at all — which is the entire point of the forward direction. There is
     * nothing to put in `account_id` for those, and inventing an account to satisfy a
     * constraint would be a worse outcome than a rollback that stops and says why.
     */
    public function down(): void
    {
        $accountless = DB::table('projects')->whereNull('account_id')->count();

        if ($accountless > 0) {
            throw new RuntimeException(
                "{$accountless} project(s) are owned by an organization with no account. "
                .'Restoring the NOT NULL constraint would require inventing an account for '
                .'each; delete or re-home them first.'
            );
        }

        Schema::withoutForeignKeyConstraints(function (): void {
            Schema::table('projects', function (Blueprint $table): void {
                $table->string('account_id', 26)->nullable(false)->change();
            });
        });
    }
};
