<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Testing;

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\FeatureFlags\Models\FeatureFlag;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Cbox\Id\FeatureFlags\ValueObjects\NewFeatureFlag;
use PHPUnit\Framework\Assert;

/**
 * Drop-in test ergonomics for feature flags, shipped with the package so downstream
 * consumers get the same fluency:
 *
 *     use Cbox\Id\FeatureFlags\Testing\InteractsWithFeatureFlags;
 *
 *     uses(InteractsWithFeatureFlags::class);
 *
 *     it('shows the beta to Acme only', function () {
 *         $this->createFeatureFlag('new-dashboard', FlagTargeting::organizations([$acme->id]));
 *         $this->assertFeatureEnabled('new-dashboard', $user->id, $acme->id);
 *         $this->assertFeatureDisabled('new-dashboard', $user->id, $globex->id);
 *     });
 */
trait InteractsWithFeatureFlags
{
    protected function createFeatureFlag(
        string $key,
        ?FlagTargeting $targeting = null,
        bool $defaultValue = false,
        bool $enabled = true,
    ): FeatureFlag {
        return app(FeatureFlags::class)->create(new NewFeatureFlag(
            key: $key,
            enabled: $enabled,
            defaultValue: $defaultValue,
            targeting: $targeting ?? FlagTargeting::none(),
        ));
    }

    protected function assertFeatureEnabled(string $key, ?string $subjectId, ?string $organizationId = null): void
    {
        Assert::assertTrue(
            app(FeatureFlags::class)->isEnabled($key, $subjectId, $organizationId),
            "Expected the feature flag [{$key}] to be on.",
        );
    }

    protected function assertFeatureDisabled(string $key, ?string $subjectId, ?string $organizationId = null): void
    {
        Assert::assertFalse(
            app(FeatureFlags::class)->isEnabled($key, $subjectId, $organizationId),
            "Expected the feature flag [{$key}] to be off.",
        );
    }
}
