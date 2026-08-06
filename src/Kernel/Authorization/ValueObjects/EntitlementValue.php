<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;

/**
 * A resolved entitlement value with its provenance and enforcement mode.
 */
readonly class EntitlementValue
{
    /**
     * @param  array<string, mixed>  $value
     */
    public function __construct(
        public string $key,
        public array $value,
        public EnforcementMode $mode,
        public EntitlementSource $source,
        public int $version,
    ) {}

    public function bool(string $key = 'enabled'): bool
    {
        return (bool) ($this->value[$key] ?? false);
    }

    public function int(string $key): ?int
    {
        $value = $this->value[$key] ?? null;

        return is_int($value) ? $value : (is_numeric($value) ? (int) $value : null);
    }

    public function string(string $key): ?string
    {
        $value = $this->value[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
