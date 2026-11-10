<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Support;

use Cbox\Id\Kernel\Authorization\Contracts\ScopeAliases;
use Cbox\Id\Kernel\Authorization\NoScopeAliases;

/**
 * Scope comparison through the host's {@see ScopeAliases}.
 *
 * Static, because the checks it serves live on models and value objects (a client's
 * registration, a key, an introspected token) that cannot take a constructor dependency.
 * Every scope check in the package goes through here, so a host's registry is honoured
 * everywhere or nowhere.
 */
final class Scopes
{
    /**
     * Whether a holder of $held may act under $required: it holds that scope under its
     * current name or under any other name of it.
     *
     * @param  iterable<mixed>  $held
     */
    public static function satisfies(iterable $held, string $required): bool
    {
        $aliases = self::aliases();
        $wanted = $aliases->canonical($required);

        foreach ($held as $scope) {
            if (is_string($scope) && ($scope === $required || $aliases->canonical($scope) === $wanted)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The current names of $scopes, in order, without duplicates.
     *
     * @param  list<string>  $scopes
     * @return list<string>
     */
    public static function canonicalise(array $scopes): array
    {
        $aliases = self::aliases();

        return array_values(array_unique(array_map($aliases->canonical(...), $scopes)));
    }

    private static function aliases(): ScopeAliases
    {
        return app()->bound(ScopeAliases::class)
            ? app(ScopeAliases::class)
            : new NoScopeAliases;
    }
}
