<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\ValueObjects;

/**
 * What to change on an existing flag. Every part is optional: only what a `with…()` call
 * named is changed, so a caller that only flips `enabled` cannot clobber a description or
 * a targeting set it never read. The key is not here — it is fixed once created.
 */
final readonly class FeatureFlagChanges
{
    private function __construct(
        public bool $changesDescription = false,
        public ?string $description = null,
        public ?bool $enabled = null,
        public ?bool $defaultValue = null,
        public ?FlagTargeting $targeting = null,
    ) {}

    public static function make(): self
    {
        return new self;
    }

    public function withDescription(?string $description): self
    {
        return new self(true, $description, $this->enabled, $this->defaultValue, $this->targeting);
    }

    public function withEnabled(bool $enabled): self
    {
        return new self($this->changesDescription, $this->description, $enabled, $this->defaultValue, $this->targeting);
    }

    public function withDefaultValue(bool $defaultValue): self
    {
        return new self($this->changesDescription, $this->description, $this->enabled, $defaultValue, $this->targeting);
    }

    /** Replace the whole rule set — users, organizations and rollout — with this one. */
    public function withTargeting(FlagTargeting $targeting): self
    {
        return new self($this->changesDescription, $this->description, $this->enabled, $this->defaultValue, $targeting);
    }

    public function isEmpty(): bool
    {
        return ! $this->changesDescription && $this->enabled === null && $this->defaultValue === null && $this->targeting === null;
    }
}
