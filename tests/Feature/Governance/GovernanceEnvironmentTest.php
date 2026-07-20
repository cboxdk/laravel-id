<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Enums\CampaignStatus;
use Cbox\Id\Governance\Exceptions\UnknownCampaign;
use Cbox\Id\Governance\Models\CertificationCampaign;
use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @group isolation
 */
it('keeps campaigns invisible across environments', function (): void {
    $campaignId = $this->runAsEnvironment('env_a', function (): string {
        $role = app(Roles::class)->define('acme', 'admin');
        app(Roles::class)->assign('acme', 'user-1', $role->id);

        return app(AccessReviews::class)->open('acme', 'review')->id;
    });

    // From env_b the campaign is structurally invisible, and close() cannot reach it.
    $this->runAsEnvironment('env_b', function () use ($campaignId): void {
        expect(CertificationCampaign::query()->whereKey($campaignId)->first())->toBeNull()
            ->and(fn () => app(AccessReviews::class)->close($campaignId, 'acme'))
            ->toThrow(UnknownCampaign::class);
    });

    // It still resolves in its own environment.
    $this->runAsEnvironment('env_a', function () use ($campaignId): void {
        expect(CertificationCampaign::query()->whereKey($campaignId)->first())->not->toBeNull();
    });
})->group('isolation');

it('refuses to open a campaign with no environment in context', function (): void {
    $this->forgetEnvironment();

    app(AccessReviews::class)->open('acme', 'review');
})->throws(EnvironmentMissing::class);

it('auto-closes overdue campaigns via the scheduled command, reconstructing each environment', function (): void {
    // An overdue campaign in env_a, with one un-reviewed grant.
    $campaignId = $this->runAsEnvironment('env_a', function (): string {
        $role = app(Roles::class)->define('acme', 'admin');
        app(Roles::class)->assign('acme', 'user-1', $role->id);

        return app(AccessReviews::class)->open('acme', 'review', now()->subDay())->id;
    });

    // The command runs with no ambient environment; it must find and re-enter env_a.
    $this->forgetEnvironment();
    $this->artisan('cbox-id:governance:close-overdue')->assertSuccessful();

    $this->runAsEnvironment('env_a', function () use ($campaignId): void {
        $campaign = CertificationCampaign::query()->whereKey($campaignId)->firstOrFail();
        expect($campaign->status)->toBe(CampaignStatus::Closed)
            // Pending-at-close under the default policy → the grant was auto-revoked.
            ->and(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toBe([]);
    });
})->group('isolation');
