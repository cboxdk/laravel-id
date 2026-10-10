<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Erasure;

use Cbox\Id\FeatureFlags\Enums\TargetType;
use Cbox\Id\FeatureFlags\Models\FeatureFlag;
use Cbox\Id\FeatureFlags\Models\FeatureFlagTarget;
use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Illuminate\Support\Facades\Cache;

/**
 * Every flag rule that names the erased subject, DELETED. A rule is nothing but "this
 * person gets this feature"; with the person gone there is nothing left for it to say.
 * Organization rules and the flags themselves are not the person's and stay.
 */
class FeatureFlagTargetsErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'feature_flags.targets';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $environments = FeatureFlagTarget::query()
            ->where('target_type', TargetType::User->value)
            ->where('target_id', $request->subjectId)
            ->distinct()
            ->pluck('environment_id')
            ->all();

        $deleted = FeatureFlagTarget::query()
            ->where('target_type', TargetType::User->value)
            ->where('target_id', $request->subjectId)
            ->toBase()
            ->delete();

        // A bulk delete fires no model events, so the compiled flag set is forgotten here.
        foreach ($environments as $environmentId) {
            if (is_string($environmentId)) {
                Cache::forget(FeatureFlag::cacheKey($environmentId));
            }
        }

        return ErasureStepResult::of($this->name(), ['feature_flag_targets' => $deleted]);
    }
}
