<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Support;

use Cbox\Id\Scim\ScimSchema;

/**
 * Translates a platform user's attributes into a SCIM 2.0 `User` attribute bag,
 * driven by a connection's mapping. A mapping entry is `scimPath => sourceKey`:
 * the value at `sourceKey` in the platform snapshot is placed at the SCIM
 * attribute `scimPath` (dot-notation for sub-attributes, e.g. `name.formatted`).
 *
 * The `emails` path is treated specially — a single source value becomes the
 * RFC 7643 multi-valued form `[{value, primary: true}]`. `active` is not mapped
 * from source data; it is set from the lifecycle operation itself.
 *
 * A host refines provisioning by storing a different mapping on the connection
 * (see docs/extension-points/custom-scim-attribute-mapping.md); nothing here is
 * hard-coded to the platform's own user shape beyond the default fallback.
 */
class AttributeMapping
{
    /**
     * The default mapping when a connection defines none — the attributes every
     * IdP/SCIM app expects: userName + email + a display/formatted name.
     *
     * @var array<string, string>
     */
    public const DEFAULTS = [
        'userName' => 'email',
        'displayName' => 'name',
        'name.formatted' => 'name',
        'emails' => 'email',
    ];

    /**
     * Build the mapped SCIM attribute bag (no `schemas`/`externalId` — those are
     * added by {@see ScimSchema::userResource()}), always stamping `active`.
     *
     * @param  array<string, mixed>  $mapping  scimPath => sourceKey
     * @param  array<string, mixed>  $source  platform attribute snapshot (email, name, …)
     * @return array<string, mixed>
     */
    public static function toAttributes(array $mapping, array $source, bool $active): array
    {
        $mapping = $mapping === [] ? self::DEFAULTS : $mapping;

        $attributes = [];

        foreach ($mapping as $scimPath => $sourceKey) {
            if (! is_string($sourceKey)) {
                continue;
            }

            if (! array_key_exists($sourceKey, $source)) {
                continue;
            }

            $value = $source[$sourceKey];

            if ($value === null || $value === '') {
                continue;
            }

            self::assign($attributes, $scimPath, $value);
        }

        $attributes['active'] = $active;

        return $attributes;
    }

    /**
     * Build the full `User` resource body for a create (POST) / replace (PUT).
     *
     * @param  array<string, mixed>  $mapping
     * @param  array<string, mixed>  $source
     * @return array<string, mixed>
     */
    public static function resource(string $externalId, array $mapping, array $source, bool $active): array
    {
        return ScimSchema::userResource($externalId, self::toAttributes($mapping, $source, $active));
    }

    /**
     * Build the `Operations` list for a PATCH (RFC 7644 §3.5.2) — a `replace` for
     * every mapped top-level attribute, so an update overwrites exactly what the
     * mapping produces (including `active`).
     *
     * @param  array<string, mixed>  $mapping
     * @param  array<string, mixed>  $source
     * @return list<array{op: string, path: string, value: mixed}>
     */
    public static function patchOperations(array $mapping, array $source, bool $active): array
    {
        $operations = [];

        foreach (self::toAttributes($mapping, $source, $active) as $path => $value) {
            $operations[] = ScimSchema::replace($path, $value);
        }

        return $operations;
    }

    /**
     * Place a value at a (possibly nested) SCIM path in the attribute bag.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function assign(array &$attributes, string $scimPath, mixed $value): void
    {
        // Multi-valued emails: a scalar source becomes the canonical work-email form.
        if ($scimPath === 'emails') {
            $attributes['emails'] = [['value' => $value, 'primary' => true, 'type' => 'work']];

            return;
        }

        if (! str_contains($scimPath, '.')) {
            $attributes[$scimPath] = $value;

            return;
        }

        [$head, $tail] = explode('.', $scimPath, 2);
        $existing = $attributes[$head] ?? [];

        if (! is_array($existing)) {
            $existing = [];
        }

        $existing[$tail] = $value;
        $attributes[$head] = $existing;
    }
}
