<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Console;

use Cbox\Id\Kernel\Crypto\Contracts\MasterKeyRing;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Contracts\SecretRewrapper;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Illuminate\Console\Command;

/**
 * `cbox-id:crypto:rewrap` — re-seal every registered secret under the current master key.
 *
 * The second step of a master-key rotation (see docs/security/key-management.md): after
 * the new key is `CBOX_ID_CRYPTO_KEY` and the old one is in
 * `CBOX_ID_CRYPTO_PREVIOUS_KEYS`, this moves every ciphertext onto the new key so the old
 * one can be dropped. Safe to interrupt and re-run — it only ever touches what is not yet
 * current. A thin adapter over {@see SecretRewrapper}.
 */
class RewrapSecretsCommand extends Command
{
    protected $signature = 'cbox-id:crypto:rewrap
        {--dry-run : Count what would be re-sealed without writing anything}
        {--chunk=500 : Rows read per query}
        {--column=* : Only these columns (table.column); default every registered one}';

    protected $description = 'Re-seal every stored secret under the current crypto master key';

    public function handle(SealedColumns $columns, SecretRewrapper $rewrapper, MasterKeyRing $keys): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $chunkOption = $this->option('chunk');
        $chunk = is_string($chunkOption) && ctype_digit($chunkOption) ? max(1, (int) $chunkOption) : 500;

        $selected = $this->selected($columns->all());

        if ($selected === null) {
            return self::FAILURE;
        }

        $this->line(sprintf(
            '  Current master key <options=bold>%s</>%s%s',
            $keys->currentKeyId(),
            $keys->previousKeyIds() !== [] ? '; previous: '.implode(', ', $keys->previousKeyIds()) : '; no previous keys configured',
            $dryRun ? ' <fg=yellow>(dry run — nothing is written)</>' : '',
        ));

        $failed = 0;

        foreach ($selected as $column) {
            $outcome = $rewrapper->rewrap($column, $chunk, $dryRun, function (int $processed) use ($column): void {
                $this->line("    <fg=gray>{$column->name()}: {$processed} processed…</>");
            });

            if ($outcome->skipped) {
                $this->line("  <fg=gray>-</> {$column->name()}: table not present, skipped");

                continue;
            }

            $verb = $dryRun ? 'would re-seal' : 're-sealed';
            $mark = $outcome->failed > 0 ? '<fg=red>✗</>' : '<fg=green>✓</>';

            $this->line("  {$mark} {$column->name()}: {$verb} {$outcome->rewrapped}, failed {$outcome->failed}, still not current {$outcome->remaining}");

            if ($outcome->failedKeys !== []) {
                $this->line('     <fg=red>Could not open (no configured key, or the row was tampered with): '.implode(', ', $outcome->failedKeys).'</>');
            }

            $failed += $outcome->failed;
        }

        if ($failed > 0) {
            $this->error("  {$failed} value(s) could not be opened with any configured key. Do NOT drop a previous key until they are resolved.");

            return self::FAILURE;
        }

        $this->info($dryRun ? '  Dry run complete.' : '  Every registered secret is sealed under the current key.');

        return self::SUCCESS;
    }

    /**
     * The columns to walk: all of them, or those named with --column. An unknown name is
     * an error, not an empty run — a typo must not read as "nothing to do".
     *
     * @param  list<SealedColumn>  $all
     * @return list<SealedColumn>|null
     */
    private function selected(array $all): ?array
    {
        $wanted = $this->option('column');

        if (! is_array($wanted) || $wanted === []) {
            return $all;
        }

        $byName = [];

        foreach ($all as $column) {
            $byName[$column->name()] = $column;
        }

        $selected = [];

        foreach ($wanted as $name) {
            $name = is_string($name) ? $name : '';

            if (! isset($byName[$name])) {
                $this->error("  Unknown sealed column '{$name}'. Registered: ".implode(', ', array_keys($byName)));

                return null;
            }

            $selected[] = $byName[$name];
        }

        return $selected;
    }
}
