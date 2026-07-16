<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\ValueObjects;

use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Licensing\Exceptions\LicenseException;

/**
 * A decoded on-prem license: who it's for, what it grants, and when it's valid.
 * It carries a set of entitlement grants that apply deployment-wide (the whole
 * self-hosted install is licensed, not a single org), which the licensing layer
 * overlays onto the entitlement reader.
 */
final readonly class License
{
    /**
     * @param  array<string, array<string, mixed>>  $entitlements  entitlement key => value map
     * @param  list<string>  $domains  licensed hostnames ([] = unbound)
     */
    public function __construct(
        public string $id,
        public string $customer,
        public ?string $deployment,
        public array $domains,
        public string $plan,
        public array $entitlements,
        public int $issuedAt,
        public int $notBefore,
        public int $expiresAt,
    ) {}

    /**
     * The license's grants as resolved entitlement values (source: license). The
     * version is the issue time, so re-issuing a license busts the entitlement
     * cache the same way a billing push does.
     *
     * @return array<string, EntitlementValue>
     */
    public function entitlementValues(): array
    {
        $values = [];

        foreach ($this->entitlements as $key => $value) {
            $values[$key] = new EntitlementValue(
                key: $key,
                value: $value,
                mode: EnforcementMode::DecisionApi,
                source: EntitlementSource::License,
                version: $this->issuedAt,
            );
        }

        return $values;
    }

    public function grants(string $key): bool
    {
        return array_key_exists($key, $this->entitlements);
    }

    /**
     * Build the signed-claims payload (compact keys keep the token short).
     *
     * @return array<string, mixed>
     */
    public function toClaims(): array
    {
        return [
            'lid' => $this->id,
            'sub' => $this->customer,
            'dep' => $this->deployment,
            'dom' => $this->domains,
            'plan' => $this->plan,
            'ent' => $this->entitlements,
            'iat' => $this->issuedAt,
            'nbf' => $this->notBefore,
            'exp' => $this->expiresAt,
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws LicenseException when a required claim is missing or ill-typed
     */
    public static function fromClaims(array $claims): self
    {
        return new self(
            id: self::str($claims, 'lid'),
            customer: self::str($claims, 'sub'),
            deployment: self::optionalStr($claims, 'dep'),
            domains: self::strList($claims['dom'] ?? []),
            plan: self::str($claims, 'plan'),
            entitlements: self::entitlementMap($claims['ent'] ?? []),
            issuedAt: self::int($claims, 'iat'),
            notBefore: self::int($claims, 'nbf'),
            expiresAt: self::int($claims, 'exp'),
        );
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private static function str(array $claims, string $key): string
    {
        $value = $claims[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw LicenseException::malformed("missing or invalid '{$key}'");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private static function optionalStr(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private static function int(array $claims, string $key): int
    {
        $value = $claims[$key] ?? null;

        if (! is_int($value)) {
            throw LicenseException::malformed("missing or invalid '{$key}'");
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private static function strList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $item) {
            if (is_string($item) && $item !== '') {
                $out[] = $item;
            }
        }

        return $out;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private static function entitlementMap(mixed $value): array
    {
        if (! is_array($value)) {
            throw LicenseException::malformed("invalid 'ent'");
        }

        $map = [];

        foreach ($value as $key => $entry) {
            if (is_string($key) && is_array($entry)) {
                /** @var array<string, mixed> $entry */
                $map[$key] = $entry;
            }
        }

        return $map;
    }
}
