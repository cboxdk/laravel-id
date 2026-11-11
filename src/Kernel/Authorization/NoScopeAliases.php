<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\ScopeAliases;

/** The default {@see ScopeAliases}: no scope has another name. */
class NoScopeAliases implements ScopeAliases
{
    public function canonical(string $scope): string
    {
        return $scope;
    }
}
