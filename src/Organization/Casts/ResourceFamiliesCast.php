<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Casts;

use Cbox\Id\Organization\ValueObjects\ResourceFamilies;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Casts the `resource_families` JSON column to {@see ResourceFamilies}.
 *
 * Deliberately NOT the built-in `array` cast: that one hands back a plain array
 * in which `null` and `[]` are two values a caller has to remember to tell
 * apart, and the whole reason this type exists is that forgetting to fails open.
 * Going through the value object on the way in AND out means the distinction is
 * carried by the type from the column to the call site.
 *
 * @implements CastsAttributes<ResourceFamilies, ResourceFamilies|list<string>|null>
 */
final class ResourceFamiliesCast implements CastsAttributes
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ResourceFamilies
    {
        return ResourceFamilies::fromStorage(
            is_string($value) ? json_decode($value, true, 512, JSON_THROW_ON_ERROR) : $value,
        );
    }

    /**
     * @param  array<string, mixed>  $attributes
     * @return array<string, string|null>
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): array
    {
        $families = $value instanceof ResourceFamilies ? $value : ResourceFamilies::fromStorage($value);
        $stored = $families->toStorage();

        return [$key => $stored === null ? null : json_encode($stored, JSON_THROW_ON_ERROR)];
    }
}
