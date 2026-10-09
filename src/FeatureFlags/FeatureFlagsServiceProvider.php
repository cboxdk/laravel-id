<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags;

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\FeatureFlags\Erasure\FeatureFlagTargetsErasureStep;
use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Support\PackageConfigMerger;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class FeatureFlagsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(FeatureFlags::class, DatabaseFeatureFlags::class);

        // This module's share of a GDPR erasure: the rules that name the person.
        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(FeatureFlagTargetsErasureStep::class));
        });
    }
}
