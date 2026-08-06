<?php

declare(strict_types=1);

namespace Cbox\Id\Maintenance\Console;

use Cbox\Id\Maintenance\Enums\PrunableTable;
use Cbox\Id\Maintenance\MaintenanceServiceProvider;
use Cbox\Id\Maintenance\Pruner;
use Cbox\Id\Maintenance\ValueObjects\PruneOutcome;
use Illuminate\Console\Command;

/**
 * `cbox-id:prune` — delete rows the platform no longer needs.
 *
 * Scheduled daily by {@see MaintenanceServiceProvider}, or run by
 * hand. `--dry-run` counts without deleting, which is the right first move on a
 * deployment that has never been swept and may have a very large first pass.
 *
 * See {@see Pruner} for the retention rules, and for why `audit_logs` is deliberately
 * not in scope.
 */
class PruneCommand extends Command
{
    protected $signature = 'cbox-id:prune
        {--table=* : Only these tables (default: all)}
        {--chunk= : Rows to delete per statement}
        {--dry-run : Count what would be deleted, delete nothing}';

    protected $description = 'Delete expired and terminal rows from the platform\'s growing tables.';

    public function handle(Pruner $pruner): int
    {
        $tables = $this->selectedTables();

        if ($tables === null) {
            return self::FAILURE;
        }

        $chunk = $this->chunkOption();
        $dryRun = $this->option('dry-run') === true;

        if ($dryRun) {
            $this->comment('Dry run — nothing will be deleted.');
        }

        $rows = [];
        $total = 0;

        foreach ($tables as $table) {
            $outcome = $pruner->prune($table, $chunk, $dryRun);
            $total += $outcome->deleted;
            $rows[] = $this->row($outcome);
        }

        $this->table(['Table', 'Retention', 'Cutoff', $dryRun ? 'Would delete' : 'Deleted'], $rows);
        $this->info(($dryRun ? 'Would delete ' : 'Deleted ').$total.' row(s).');

        // Stated every run so nobody reads a clean prune report as "everything is
        // bounded now" — audit growth still needs the streaming/archive path.
        $this->line('<fg=gray>audit_logs is never pruned: it is a hash-chained, checkpoint-anchored trail and deleting from it would break tamper verification.</>');

        return self::SUCCESS;
    }

    /**
     * @return list<PrunableTable>|null null when an unknown table was named
     */
    private function selectedTables(): ?array
    {
        /** @var list<string> $names */
        $names = array_values(array_filter(
            (array) $this->option('table'),
            static fn (mixed $name): bool => is_string($name) && $name !== '',
        ));

        if ($names === []) {
            return PrunableTable::cases();
        }

        $selected = [];

        foreach ($names as $name) {
            $table = PrunableTable::tryFrom($name);

            if ($table === null) {
                $this->error("Unknown table '{$name}'. Known: ".implode(', ', array_map(
                    static fn (PrunableTable $case): string => $case->value,
                    PrunableTable::cases(),
                )));

                return null;
            }

            $selected[] = $table;
        }

        return $selected;
    }

    private function chunkOption(): ?int
    {
        $chunk = $this->option('chunk');

        return is_numeric($chunk) ? max(1, (int) $chunk) : null;
    }

    /**
     * @return list<string>
     */
    private function row(PruneOutcome $outcome): array
    {
        if ($outcome->wasSkipped()) {
            return [$outcome->table->value, '—', '—', 'skipped ('.$outcome->skippedReason.')'];
        }

        return [
            $outcome->table->value,
            $outcome->retentionDays.'d',
            $outcome->cutoff?->toDateTimeString() ?? '—',
            (string) $outcome->deleted,
        ];
    }
}
