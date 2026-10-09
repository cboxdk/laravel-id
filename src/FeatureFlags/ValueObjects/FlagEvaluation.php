<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\ValueObjects;

use Cbox\Id\FeatureFlags\Enums\EvaluationReason;

/**
 * One flag's answer for one subject, and the rule that gave it — so a support engineer
 * asking "why does Acme see the new dashboard?" gets `organization_target`, not a shrug.
 */
final readonly class FlagEvaluation
{
    public function __construct(
        public string $key,
        public bool $enabled,
        public EvaluationReason $reason,
    ) {}

    public static function unknown(string $key): self
    {
        return new self($key, false, EvaluationReason::UnknownFlag);
    }

    /**
     * @return array{key: string, enabled: bool, reason: string}
     */
    public function toArray(): array
    {
        return ['key' => $this->key, 'enabled' => $this->enabled, 'reason' => $this->reason->value];
    }
}
