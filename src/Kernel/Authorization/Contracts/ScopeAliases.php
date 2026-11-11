<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Contracts;

use Cbox\Id\Kernel\Authorization\NoScopeAliases;

/**
 * The host's scope registry, as far as this package needs it: which name a scope goes by
 * now.
 *
 * Scope names change (`workspace:read` became `id:organization:read`), and the tokens,
 * keys and client registrations already issued hold the old ones. Binding this lets the
 * host's registry decide, in one place, that an old name and its new name are the same
 * scope. Every scope check in the package then treats them as one — an access token,
 * an environment key, an organization key and a client registration holding either name
 * satisfies a check for either — and a grant hands back the name {@see canonical()}
 * returns, so a client that asks for an old name receives the new one.
 *
 * The bundled {@see NoScopeAliases} knows no aliases: every
 * scope is only itself, exactly as before the hook existed.
 */
interface ScopeAliases
{
    /** The current name of $scope. A scope that has no other name returns itself. */
    public function canonical(string $scope): string;
}
