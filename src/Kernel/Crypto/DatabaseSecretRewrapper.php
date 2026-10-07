<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\MasterKeyRing;
use Cbox\Id\Kernel\Crypto\Contracts\SecretRewrapper;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\ValueObjects\RewrapOutcome;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Closure;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The default {@see SecretRewrapper}, over the raw query builder.
 *
 * UNSCOPED ON PURPOSE. A master key is deployment-wide, so its rotation is too: every
 * environment's rows are re-sealed in one pass. The environment-owned Eloquent models
 * would silently narrow each query to whichever environment the console happened to be
 * in (or to nothing at all), leaving every other tenant's secrets on the old key — the
 * same reason `cbox-id:prune` reads raw tables.
 *
 * KEYSET, NOT OFFSET. Each chunk continues from the last key it saw, and only selects
 * values not yet current. A value that cannot be opened stays behind the cursor instead
 * of being re-read forever, and the rows being rewritten never shift a page boundary.
 *
 * COMPARE-AND-SET. A value is written back only where it is still exactly what was read,
 * so a secret rotated by its owner mid-pass (a webhook secret, a re-enrolled TOTP) is
 * never overwritten with a re-sealed copy of the old one.
 */
class DatabaseSecretRewrapper implements SecretRewrapper
{
    /** Rows named in an outcome's failure list — enough to start looking, not a dump. */
    private const FAILED_KEYS_REPORTED = 20;

    public function __construct(
        private readonly MasterKeyRing $keys,
    ) {}

    public function rewrap(SealedColumn $column, int $chunk = 500, bool $dryRun = false, ?Closure $progress = null): RewrapOutcome
    {
        if (! $this->present($column)) {
            return RewrapOutcome::skipped($column);
        }

        $chunk = max(1, $chunk);
        $cursor = null;
        $rewrapped = 0;
        $failed = 0;
        $failedKeys = [];

        do {
            $query = $this->notCurrent($column)
                ->select([$column->keyColumn, $column->column, $column->contextColumn])
                ->orderBy($column->keyColumn)
                ->limit($chunk);

            if ($cursor !== null) {
                $query->where($column->keyColumn, '>', $cursor);
            }

            $rows = $query->get();

            foreach ($rows as $row) {
                $values = (array) $row;
                $key = self::string($values[$column->keyColumn] ?? null);
                $sealed = self::string($values[$column->column] ?? null);
                $cursor = $key;

                try {
                    $resealed = $this->keys->rewrap($sealed, $column->contextFor(self::string($values[$column->contextColumn] ?? null)));
                } catch (DecryptionFailed) {
                    $failed++;

                    if (count($failedKeys) < self::FAILED_KEYS_REPORTED) {
                        $failedKeys[] = $key;
                    }

                    continue;
                }

                if (! $dryRun) {
                    DB::table($column->table)
                        ->where($column->keyColumn, $key)
                        ->where($column->column, $sealed)
                        ->update([$column->column => $resealed]);
                }

                $rewrapped++;
            }

            if ($progress !== null && $rows->isNotEmpty()) {
                $progress($rewrapped + $failed);
            }
        } while ($rows->count() === $chunk);

        return new RewrapOutcome(
            column: $column,
            rewrapped: $rewrapped,
            failed: $failed,
            remaining: $this->remaining($column),
            dryRun: $dryRun,
            failedKeys: $failedKeys,
        );
    }

    public function remaining(SealedColumn $column): int
    {
        return $this->present($column) ? $this->notCurrent($column)->count() : 0;
    }

    /**
     * Every non-empty value in the column that does not carry the current key's prefix.
     * The prefix is `v1.<hex>.` — no LIKE wildcard can appear in it.
     */
    private function notCurrent(SealedColumn $column): Builder
    {
        return DB::table($column->table)
            ->whereNotNull($column->column)
            ->where($column->column, '!=', '')
            ->where($column->column, 'not like', $this->keys->currentPrefix().'%');
    }

    /** A host may install only part of the platform, so an absent table is expected. */
    private function present(SealedColumn $column): bool
    {
        return Schema::hasTable($column->table) && Schema::hasColumn($column->table, $column->column);
    }

    private static function string(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }
}
