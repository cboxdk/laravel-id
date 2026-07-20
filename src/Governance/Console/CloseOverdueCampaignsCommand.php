<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Console;

use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Enums\CampaignStatus;
use Cbox\Id\Governance\Models\CertificationCampaign;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Console\Command;

/**
 * Close every open certification campaign whose due date has passed, across EVERY
 * environment — the one genuinely environment-spanning governance step.
 *
 * It is careful to reconstruct each campaign's own environment before acting: under
 * {@see EnvironmentContext::withoutScope()} it enumerates overdue open campaigns
 * across the whole deployment (a system read), then for each one re-enters that
 * exact environment with {@see EnvironmentContext::runAs()} and calls
 * {@see AccessReviews::close()} — which applies the campaign's revokes inside the
 * right hard scope. Scheduled every minute by the service provider, or run by hand.
 */
class CloseOverdueCampaignsCommand extends Command
{
    protected $signature = 'cbox-id:governance:close-overdue';

    protected $description = 'Close every overdue open certification campaign across all environments.';

    public function handle(EnvironmentContext $context, AccessReviews $reviews): int
    {
        // System read across the environment boundary: which overdue campaigns exist,
        // and in which environment does each live.
        $overdue = $context->withoutScope(fn (): array => CertificationCampaign::query()
            ->where('status', CampaignStatus::Open->value)
            ->whereNotNull('due_at')
            ->where('due_at', '<=', now())
            ->get(['id', 'environment_id', 'organization_id'])
            ->all());

        $closed = 0;

        foreach ($overdue as $campaign) {
            // Re-enter the campaign's own environment so the hard scope matches when
            // close() reads its items and applies revokes.
            $context->runAs(
                GenericEnvironment::of($campaign->environment_id),
                // Acts in each campaign's OWN org — the system closer is not exempt from
                // the ownership check, it simply supplies the right scope per campaign.
                fn () => $reviews->close($campaign->id, $campaign->organization_id),
            );
            $closed++;
        }

        $this->info("Closed {$closed} overdue campaign(s).");

        return self::SUCCESS;
    }
}
