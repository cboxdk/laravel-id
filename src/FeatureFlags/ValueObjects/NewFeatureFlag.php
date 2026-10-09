<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\ValueObjects;

/**
 * A flag to create. A new flag is enabled and off by default — live, but on only for
 * whoever its targeting names — so creating one changes nothing for anyone until a rule
 * or the default says otherwise.
 *
 * `key` is what code asks for (`new-dashboard`) and what the `feature_flags` claim
 * carries. It is fixed once created: it is the name every caller already uses, and the
 * rollout bucket is derived from it.
 */
final readonly class NewFeatureFlag
{
    public function __construct(
        public string $key,
        public ?string $description = null,
        public bool $enabled = true,
        public bool $defaultValue = false,
        public FlagTargeting $targeting = new FlagTargeting,
    ) {}
}
