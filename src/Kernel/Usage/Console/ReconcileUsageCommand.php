<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Console;

use Cbox\Id\Kernel\Usage\UsageReconciler;
use Cbox\Id\Organization\Models\Organization;
use Illuminate\Console\Command;

/**
 * Reconciles the usage meter against ground truth for every organization (or one via
 * --org), correcting any drift. Wire it into the scheduler (e.g. daily) as the safety
 * net beneath the at-least-once metering outbox. Runs in the current environment
 * scope — schedule it per environment if you host several.
 */
final class ReconcileUsageCommand extends Command
{
    protected $signature = 'cbox-id:reconcile-usage {--org= : Reconcile only this organization id}';

    protected $description = 'Detect and correct drift between the usage meter and ground truth (seats).';

    public function handle(UsageReconciler $reconciler): int
    {
        $org = $this->option('org');

        if (is_string($org) && $org !== '') {
            $organizationIds = [$org];
        } else {
            $organizationIds = [];
            foreach (Organization::query()->pluck('id') as $id) {
                if (is_string($id) && $id !== '') {
                    $organizationIds[] = $id;
                }
            }
        }

        $drifted = 0;

        foreach ($organizationIds as $organizationId) {
            $result = $reconciler->reconcileMembership($organizationId);

            if ($result->driftDetected()) {
                $drifted++;
                $this->warn(sprintf(
                    '%s: seats drift %+d (expected %d, metered %d) — corrected',
                    $result->organizationId,
                    $result->drift,
                    $result->expected,
                    $result->metered,
                ));
            }
        }

        $this->info(sprintf('Reconciled %d organization(s); %d had drift.', count($organizationIds), $drifted));

        return self::SUCCESS;
    }
}
