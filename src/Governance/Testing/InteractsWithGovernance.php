<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Testing;

use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Governance\Models\CertificationCampaign;
use Cbox\Id\Governance\Models\SodPolicy;
use DateTimeInterface;

/**
 * Drop-in test ergonomics for access governance, shipped with the package so
 * downstream consumers get the same fluency:
 *
 *     use Cbox\Id\Governance\Testing\InteractsWithGovernance;
 *
 *     uses(InteractsWithGovernance::class);
 *
 *     it('reviews access', function () {
 *         $campaign = $this->openAccessReview('acme', 'Q3 review');
 *         // ... certify / revoke items, then close ...
 *     });
 */
trait InteractsWithGovernance
{
    protected function openAccessReview(
        string $organizationId,
        string $name = 'Access review',
        ?DateTimeInterface $dueAt = null,
        PendingPolicy $pendingPolicy = PendingPolicy::Revoke,
    ): CertificationCampaign {
        return app(AccessReviews::class)->open($organizationId, $name, $dueAt, $pendingPolicy);
    }

    /**
     * @param  list<string>  $roleIds
     */
    protected function defineSodPolicy(?string $organizationId, string $name, array $roleIds): SodPolicy
    {
        return app(SegregationOfDuties::class)->definePolicy($organizationId, $name, $roleIds);
    }
}
