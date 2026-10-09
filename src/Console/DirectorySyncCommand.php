<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Exceptions\DirectorySyncInProgress;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Console\Command;

/**
 * Pulls users from every active API-pull directory (Google Workspace, Entra, and the HR
 * systems — Workday, BambooHR, Rippling, HiBob, Personio) across all environments and
 * reconciles them — provisioning joiners/updates and deprovisioning leavers. Each
 * directory is synced in its own environment scope; a connection failure on one
 * directory is recorded and never stops the others.
 *
 * `--due` is what the scheduler runs: only the directories whose own interval has elapsed
 * since their last run started ({@see Directory::isDueForSync()}). Without it, every
 * active pull directory is pulled now, as before. `--full` asks an HR system that syncs
 * incrementally for everybody.
 */
class DirectorySyncCommand extends Command
{
    protected $signature = 'cbox-id:directory:sync
        {--directory= : Sync only this directory id}
        {--due : Sync only the directories whose interval has elapsed}
        {--full : Ask incremental HR systems for everybody, not only what changed}';

    protected $description = 'Pull + reconcile users from API-pull directory connectors (Google Workspace, Entra, HR systems).';

    public function handle(EnvironmentContext $context, DirectoryPullSync $sync): int
    {
        $only = $this->option('directory');

        // Pull directories live across every environment, so query above the scope.
        $directories = $context->withoutScope(function () use ($only) {
            $query = Directory::query()
                ->where('provider', '!=', DirectoryProvider::Scim->value)
                ->where('status', 'active');

            if (is_string($only) && $only !== '') {
                $query->whereKey($only);
            }

            return $query->get();
        });

        if ($this->option('due') === true) {
            $directories = $directories->filter(fn (Directory $directory): bool => $directory->isDueForSync())->values();
        }

        $failures = 0;
        $full = $this->option('full') === true;

        foreach ($directories as $directory) {
            try {
                $result = $sync->sync($directory, $full);
                $partial = $result->partial() ? " <comment>({$result->failed} could not be synced)</comment>" : '';
                $this->line("  <info>✓</info> {$directory->name} ({$directory->provider->label()}): +{$result->provisioned} / −{$result->deprovisioned}{$partial}");
            } catch (DirectorySyncInProgress) {
                $this->line("  <comment>…</comment> {$directory->name}: already syncing, skipped.");
            } catch (DirectoryConnectionFailed $e) {
                $failures++;
                $this->line("  <error>✗</error> {$directory->name}: {$e->getMessage()}");
            }
        }

        $this->info("Synced {$directories->count()} director".($directories->count() === 1 ? 'y' : 'ies').", {$failures} failed.");

        return $failures === 0 ? self::SUCCESS : self::FAILURE;
    }
}
