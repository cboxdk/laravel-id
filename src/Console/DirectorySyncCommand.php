<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Console\Command;

/**
 * Pulls users from every active API-pull directory (Google Workspace, Entra) across
 * all environments and reconciles them — provisioning joiners/updates and
 * deprovisioning leavers. Intended to run on a schedule (e.g. hourly). Each
 * directory is synced in its own environment scope; a connection failure on one
 * directory is recorded and never stops the others.
 */
final class DirectorySyncCommand extends Command
{
    protected $signature = 'cbox-id:directory:sync {--directory= : Sync only this directory id}';

    protected $description = 'Pull + reconcile users from API-pull directory connectors (Google Workspace, Entra).';

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

        $failures = 0;

        foreach ($directories as $directory) {
            try {
                $result = $sync->sync($directory);
                $this->line("  <info>✓</info> {$directory->name} ({$directory->provider->label()}): +{$result->provisioned} / −{$result->deprovisioned}");
            } catch (DirectoryConnectionFailed $e) {
                $failures++;
                $this->line("  <error>✗</error> {$directory->name}: {$e->getMessage()}");
            }
        }

        $this->info("Synced {$directories->count()} director".($directories->count() === 1 ? 'y' : 'ies').", {$failures} failed.");

        return $failures === 0 ? self::SUCCESS : self::FAILURE;
    }
}
