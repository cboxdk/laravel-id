<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\Schema\Grammars\Grammar;
use Illuminate\Support\Facades\Schema;

/**
 * Move every identifier column off blank-padded `CHAR` and onto `VARCHAR`.
 *
 * `$table->ulid($column)` is `$table->char($column, 26)`, and PostgreSQL implements
 * `CHAR` as the SQL-standard `bpchar` — *blank-padded* character. A value shorter
 * than the declared width is physically stored padded to it, and PDO hands those
 * bytes to PHP verbatim:
 *
 *     INSERT 'env_test' INTO char(26)
 *       octet_length(id) = 26      -- padded on disk
 *       length(id)       = 8       -- Postgres' length() strips trailing blanks
 *       id = 'env_test'            -- true; the = operator strips them too
 *
 *     read back through PDO:
 *       strlen($v)          = 26
 *       $v === 'env_test'   = FALSE
 *
 * Everything at the SQL level looks right, which is why this was invisible to
 * inspection for sixty-one releases. PHP is where it breaks, and it breaks every
 * strict comparison:
 *
 *   - `BelongsToEnvironment` compares a row's `environment_id` against the active
 *     key and throws `CrossEnvironmentAccess` ON ITS OWN ROW —
 *     `row belongs to [env_test⎵⎵⎵…], acting as [env_test]`.
 *   - `DatabaseAuditLog::canonicalPayload()` puts `organization_id` inside the chain
 *     hash. It hashes the unpadded value at write and the padded one at read, so
 *     `verifyChain()` reports `content hash mismatch (tampered)` on a chain nobody
 *     touched.
 *
 * 338 of 1358 tests failed this way on postgres:16. MySQL and MariaDB pad on disk
 * too but strip on retrieval, and SQLite has no fixed-width type at all, which is
 * why neither engine ever showed it.
 *
 * `VARCHAR` does not pad, on any of the four engines. The create migrations now say
 * `$table->string($column, 26)`, which fixes a database created from here on; this
 * migration is what fixes one that already exists.
 *
 * WHY IT IS SAFE TO REPLAY
 *
 * The type is read from the live schema rather than assumed, so a column that is
 * already `varchar` is skipped. That matters for three reasons: a fresh install runs
 * the create migrations (already varchar) and then this one, which must be a no-op;
 * `cboxdk/laravel-siem` creates `log_streams` / `stream_deliveries` with its own
 * `ulid()` calls that this package cannot edit, so those three columns are converted
 * HERE on every install, fresh or not; and the width is taken from the column itself,
 * so nothing can be silently truncated.
 *
 * WHAT IT COSTS
 *
 * PostgreSQL rewrites the table (`bpchar` and `varchar` have different physical
 * representations) under an ACCESS EXCLUSIVE lock, and takes a SHARE ROW EXCLUSIVE
 * lock on any table holding a foreign key into it. Every column of one table is
 * converted in a SINGLE `ALTER TABLE`, so each table is rewritten once, not once per
 * column. MySQL and MariaDB likewise copy the table, and additionally need the 10
 * account-plane foreign keys dropped and put back around the conversion — see
 * `foreignKeyDetour()` for why InnoDB leaves no choice. UPGRADING.md has the
 * deployment order and what that window costs.
 *
 * SQLite is skipped: its declared types carry affinity, not width, so `char(26)` and
 * `varchar(26)` are the same TEXT column and there is nothing to alter.
 */
return new class extends Migration
{
    /**
     * Every column this package's schema (plus the three that `cboxdk/laravel-siem`
     * owns) created as a blank-padded `CHAR` — 222 identifier columns at width 26,
     * and the three audit hash columns at width 64.
     *
     * Enumerated rather than discovered so this migration can never reach a column
     * the host app owns. Tables absent from a partial install are skipped.
     *
     * @var array<string, list<string>>
     */
    private const COLUMNS = [
        'account_api_keys' => ['id', 'account_id'],
        'account_member_environments' => ['account_member_id', 'environment_id'],
        'account_members' => ['id', 'account_id', 'subject_id'],
        'account_mfa_factors' => ['id', 'account_member_id'],
        'account_mfa_recovery_codes' => ['id', 'account_member_id'],
        'account_webauthn_credentials' => ['id', 'account_member_id'],
        'accounts' => ['id', 'organization_id'],
        'app_manifests' => ['id', 'environment_id'],
        'audit_checkpoints' => ['id', 'organization_id', 'root_hash'],
        'audit_logs' => ['id', 'organization_id', 'prev_hash', 'hash'],
        'auth_policies' => ['id', 'environment_id', 'organization_id'],
        'auth_sessions' => ['id', 'environment_id', 'user_id', 'organization_id'],
        'ciba_requests' => ['id', 'environment_id'],
        'connections' => ['id', 'environment_id', 'organization_id'],
        'consumed_assertions' => ['id'],
        'device_codes' => ['id', 'environment_id'],
        'directories' => ['id', 'environment_id', 'organization_id'],
        'directory_group_members' => ['group_id', 'directory_user_id'],
        'directory_groups' => ['id', 'environment_id', 'directory_id'],
        'directory_users' => ['id', 'environment_id', 'directory_id', 'user_id'],
        'dpop_proofs' => ['id', 'environment_id'],
        'email_verification_tokens' => ['id', 'environment_id'],
        'entitlement_history' => ['id', 'environment_id', 'organization_id'],
        'entitlements' => ['id', 'environment_id', 'organization_id'],
        'environment_api_keys' => ['id', 'environment_id'],
        'environments' => ['id', 'account_id', 'project_id'],
        'events' => ['id', 'organization_id', 'environment_id'],
        'external_action_endpoints' => ['id', 'environment_id', 'organization_id'],
        'governance_campaigns' => ['id', 'environment_id', 'organization_id'],
        'governance_certification_items' => ['id', 'environment_id', 'campaign_id', 'organization_id'],
        'governance_sod_policies' => ['id', 'environment_id', 'organization_id'],
        'group_role_mappings' => ['id', 'environment_id', 'organization_id', 'group_id', 'role_id'],
        'identities' => ['id', 'environment_id', 'user_id', 'connection_id'],
        'invitations' => ['id', 'organization_id', 'invited_by', 'environment_id'],
        'log_streams' => ['id', 'environment_id'],
        'login_attempt_counters' => ['id', 'environment_id', 'user_id'],
        'magic_links' => ['id', 'environment_id'],
        'memberships' => ['id', 'environment_id', 'organization_id', 'user_id', 'invited_by'],
        'mfa_factors' => ['id', 'environment_id', 'user_id'],
        'mfa_recovery_codes' => ['id', 'environment_id', 'user_id'],
        'oauth_access_tokens' => ['id', 'environment_id', 'user_id', 'organization_id'],
        'oauth_authorization_codes' => ['id', 'environment_id', 'user_id', 'organization_id'],
        'oauth_clients' => ['id', 'environment_id', 'organization_id'],
        'oauth_refresh_tokens' => ['id', 'environment_id', 'user_id', 'organization_id'],
        'oauth_service_accounts' => ['id', 'environment_id', 'organization_id'],
        'operator_mfa_factors' => ['id', 'operator_id'],
        'operator_mfa_recovery_codes' => ['id', 'operator_id'],
        'organization_closure' => ['id', 'environment_id', 'ancestor_id', 'descendant_id'],
        'organizations' => ['id', 'environment_id', 'parent_id'],
        'otp_challenges' => ['id', 'environment_id'],
        'password_ages' => ['id', 'environment_id', 'user_id'],
        'password_change_requirements' => ['id', 'environment_id', 'user_id'],
        'password_history' => ['id', 'environment_id', 'user_id'],
        'password_reset_tokens' => ['id', 'environment_id'],
        'permissions' => ['id', 'environment_id'],
        'platform_operators' => ['id'],
        'projects' => ['id', 'account_id'],
        'provisioned_resources' => ['id', 'environment_id', 'connection_id'],
        'provisioning_connections' => ['id', 'environment_id', 'organization_id'],
        'provisioning_operations' => ['id', 'environment_id', 'connection_id'],
        'pushed_authorization_requests' => ['id', 'environment_id'],
        'relationship_tuples' => ['id', 'environment_id', 'organization_id'],
        'role_assignments' => ['id', 'environment_id', 'organization_id', 'user_id', 'role_id'],
        'role_permission' => ['role_id', 'permission_id'],
        'roles' => ['id', 'environment_id', 'organization_id'],
        'saml_auth_requests' => ['id', 'environment_id'],
        'saml_idp_certificates' => ['id', 'environment_id'],
        'saml_idp_entity_ids' => ['id', 'environment_id'],
        'saml_service_providers' => ['id', 'environment_id'],
        'signing_keys' => ['id', 'environment_id'],
        'stream_deliveries' => ['id', 'stream_id', 'environment_id'],
        'usage_counters' => ['id', 'environment_id'],
        'user_api_tokens' => ['id', 'environment_id', 'organization_id', 'user_id'],
        'user_groups' => ['id', 'environment_id', 'organization_id'],
        'users' => ['id', 'environment_id'],
        'vault_grants' => ['id', 'environment_id', 'secret_id'],
        'vault_secrets' => ['id', 'environment_id'],
        'verified_domains' => ['id', 'environment_id', 'organization_id'],
        'webauthn_credentials' => ['id', 'environment_id', 'user_id'],
        'webhook_deliveries' => ['id', 'environment_id', 'endpoint_id'],
        'webhook_endpoints' => ['id', 'environment_id', 'organization_id'],
    ];

    public function up(): void
    {
        $this->retype('varchar');
    }

    public function down(): void
    {
        $this->retype('char');
    }

    /**
     * Rewrite every listed column that is not already `$target` to `$target`,
     * preserving its width, nullability and collation.
     */
    private function retype(string $target): void
    {
        $connection = Schema::getConnection();
        $driver = $connection->getDriverName();

        // sqlite stores TEXT either way; sqlsrv is not a supported engine.
        if (! in_array($driver, ['pgsql', 'mysql', 'mariadb'], true)) {
            return;
        }

        $grammar = $connection->getSchemaGrammar();

        // Via the builder rather than the `Schema` facade: the facade's `@method`
        // annotation flattens `getColumns()` to a bare `array`, and this needs the
        // real `list<array{name: string, type: string, type_name: string, ...}>` to
        // stay type-safe at PHPStan level max.
        $schema = $connection->getSchemaBuilder();

        // Each table's own default collation, so the MySQL `MODIFY` below can restate
        // a column's collation only when it actually differs from what the column
        // would inherit. Naming it unconditionally is harmless semantically but makes
        // `mysqldump` annotate every converted column with `CHARACTER SET … COLLATE …`
        // — schema drift against a fresh install for no gain.
        $tableCollations = [];

        foreach ($schema->getTables() as $table) {
            $tableCollations[$table['name']] = $table['collation'];
        }

        /** @var list<string> $allTables */
        $allTables = array_keys($tableCollations);

        // Planned in full BEFORE anything runs. A column carrying a default or a
        // generation expression cannot be re-typed by the `MODIFY` form MySQL
        // requires without restating it, so the plan aborts on one instead of
        // dropping it silently — and aborting before the first statement leaves the
        // schema untouched rather than half-converted.
        $statements = [];

        // What each table actually ends up converting, for the foreign-key pass below.
        /** @var array<string, list<string>> $converting */
        $converting = [];

        foreach (self::COLUMNS as $table => $columns) {
            if (! $schema->hasTable($table)) {
                continue;
            }

            $clauses = [];

            foreach ($schema->getColumns($table) as $column) {
                if (! in_array($column['name'], $columns, true)) {
                    continue;
                }

                // PostgreSQL names the padded type `bpchar`; MySQL and MariaDB call
                // it `char`. Anything else on these columns is a host-side change we
                // have no business rewriting.
                $current = $column['type_name'] === 'bpchar' ? 'char' : $column['type_name'];

                if ($current === $target || ! in_array($current, ['char', 'varchar'], true)) {
                    continue;
                }

                if (preg_match('/\((\d+)\)/', $column['type'], $matches) !== 1) {
                    throw new RuntimeException(sprintf(
                        '%s.%s is %s with no declared width; refusing to guess one.',
                        $table, $column['name'], $column['type'],
                    ));
                }

                if ($this->hasDefault($column['default']) || $column['generation'] !== null) {
                    throw new RuntimeException(sprintf(
                        '%s.%s carries a default or generation expression this migration would drop. '
                        .'Convert it by hand: it is an identifier column and shipped without one.',
                        $table, $column['name'],
                    ));
                }

                $name = $grammar->wrap($column['name']);
                $type = $target.'('.$matches[1].')';

                // PostgreSQL keeps the column's nullability, indexes, unique
                // constraints and foreign keys across a TYPE change and rebuilds the
                // indexes under their existing names. MySQL's MODIFY replaces the
                // whole definition, so nullability and collation are restated.
                $clauses[] = $driver === 'pgsql'
                    ? sprintf('alter column %s type %s', $name, $type)
                    : sprintf(
                        'modify %s %s%s %s',
                        $name,
                        $type,
                        $column['collation'] === null
                            || $column['collation'] === ($tableCollations[$table] ?? null)
                                ? ''
                                : ' collate '.$column['collation'],
                        $column['nullable'] ? 'null' : 'not null',
                    );

                $converting[$table][] = $column['name'];
            }

            if ($clauses !== []) {
                // One statement per table: one rewrite, one lock, whatever the
                // column count.
                $statements[] = 'alter table '.$grammar->wrapTable($table).' '.implode(', ', $clauses);
            }
        }

        if ($statements === []) {
            return;
        }

        [$dropForeignKeys, $addForeignKeys] = $this->foreignKeyDetour($schema, $grammar, $driver, $converting, $allTables);

        foreach ($dropForeignKeys as $statement) {
            $connection->statement($statement);
        }

        try {
            foreach ($statements as $statement) {
                $connection->statement($statement);
            }
        } catch (Throwable $failure) {
            // A conversion blew up with the foreign keys already out of the way, and
            // nothing outside this method's memory records what they were. Put back
            // everything that will go back, one at a time and best-effort: after a
            // partial conversion some constraints now span a `varchar` column and a
            // `char` one, and those genuinely cannot be restored until the conversion
            // is completed. Restoring eight of ten beats restoring none, and the
            // original failure is what gets rethrown.
            foreach ($addForeignKeys as $statement) {
                try {
                    $connection->statement($statement);
                } catch (Throwable) {
                    continue;
                }
            }

            throw $failure;
        }

        // On the happy path a constraint that will not go back is a real problem, so
        // this pass is NOT best-effort.
        foreach ($addForeignKeys as $statement) {
            $connection->statement($statement);
        }
    }

    /**
     * The statements that take the foreign keys out of the way and put them back.
     *
     * InnoDB refuses to re-type a column that a foreign key sits on when the change
     * would leave the two sides mismatched — `error 1832, Cannot change column
     * 'account_id': used in a foreign key constraint`. And they always are mismatched
     * for a moment: the two sides live in different tables, so they cannot be altered
     * in one statement, and whichever goes first is briefly `varchar` against the
     * other's `char`. There are 10 such constraints across the account plane.
     *
     * PostgreSQL has no such objection — it re-validates the constraint across the
     * type change and keeps the name — so this returns nothing there and the tables
     * are altered with their foreign keys in place.
     *
     * The constraints are read back from the live schema rather than hardcoded, and
     * EVERY table is scanned rather than only the ones being converted — a foreign key
     * lives on the referencing side, so a host table of your own pointing at, say,
     * `environments.id` would otherwise be invisible here and would block the
     * conversion with the same error. Whatever is found is restored with the name,
     * columns and referential actions it had.
     *
     * @param  array<string, list<string>>  $converting
     * @param  list<string>  $allTables
     * @return array{list<string>, list<string>}
     */
    private function foreignKeyDetour(
        Builder $schema,
        Grammar $grammar,
        string $driver,
        array $converting,
        array $allTables,
    ): array {
        if ($driver === 'pgsql') {
            return [[], []];
        }

        $drops = [];
        $adds = [];

        foreach ($allTables as $table) {
            foreach ($schema->getForeignKeys($table) as $foreignKey) {
                // Either end being re-typed is enough to upset InnoDB.
                $onThisSide = array_intersect($foreignKey['columns'], $converting[$table] ?? []) !== [];
                $onTheOther = array_intersect(
                    $foreignKey['foreign_columns'],
                    $converting[$foreignKey['foreign_table']] ?? [],
                ) !== [];

                if (! $onThisSide && ! $onTheOther) {
                    continue;
                }

                if ($foreignKey['name'] === null) {
                    throw new RuntimeException(sprintf(
                        'The foreign key on %s (%s) has no name, so it cannot be dropped and restored. '
                        .'Name it, or convert these columns by hand.',
                        $table, implode(', ', $foreignKey['columns']),
                    ));
                }

                $on = $grammar->wrapTable($table);
                $name = $grammar->wrap($foreignKey['name']);

                $drops[] = sprintf('alter table %s drop foreign key %s', $on, $name);

                $adds[] = sprintf(
                    'alter table %s add constraint %s foreign key (%s) references %s (%s)%s%s',
                    $on,
                    $name,
                    $grammar->columnize($foreignKey['columns']),
                    $grammar->wrapTable($foreignKey['foreign_table']),
                    $grammar->columnize($foreignKey['foreign_columns']),
                    $this->referentialAction('delete', $foreignKey['on_delete']),
                    $this->referentialAction('update', $foreignKey['on_update']),
                );
            }
        }

        return [$drops, $adds];
    }

    /**
     * `ON DELETE`/`ON UPDATE` as reported, or nothing when the engine reports the
     * default. InnoDB treats `NO ACTION` as `RESTRICT`, and reports an unspecified
     * clause as `restrict`, so restating it is a no-op rather than a change.
     */
    private function referentialAction(string $event, ?string $action): string
    {
        if ($action === null || $action === '') {
            return '';
        }

        return ' on '.$event.' '.$action;
    }

    /**
     * MariaDB reports a nullable column with no default as the four-character
     * string `NULL` rather than SQL NULL, which is not a default at all.
     */
    private function hasDefault(mixed $default): bool
    {
        return $default !== null && $default !== 'NULL';
    }
};
