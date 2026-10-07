<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\ConfiguredProtectedResources;
use Cbox\Id\OAuthServer\Exceptions\InvalidProtectedResource;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;

/**
 * The resource servers the HOST application serves itself, declared in code — beside the
 * registered APIs operators manage as data ({@see Apis}).
 *
 * Everything that asks "is this an audience we serve?" asks here as well: the audience
 * resolver, when a token request names an RFC 8707 `resource`; the RFC 9728 metadata
 * routes, which describe each one at its path-suffixed well-known URL; and the
 * self-registration paths (RFC 7591 in `mcp` mode, client ID metadata documents), which
 * may only hand a client the scopes of resources that accept self-registered clients.
 *
 * Bound to {@see ConfiguredProtectedResources}, which reads
 * `cbox-id.oauth.protected_resources`. Rebind it when the set depends on more than config
 * — a feature flag, the environment's plan — and answer per call: the binding is a
 * singleton, and every method is asked in the context of the current environment.
 */
interface ProtectedResources
{
    /**
     * Every resource declared for the current environment.
     *
     * @return list<ProtectedResource>
     *
     * @throws InvalidProtectedResource when a declaration cannot be served
     */
    public function all(): array;

    /**
     * The declared resource whose identifier is exactly `$identifier`, if any.
     */
    public function find(string $identifier): ?ProtectedResource;

    /**
     * The declared resource described at `$path` — an RFC 9728 well-known path such as
     * `/.well-known/oauth-protected-resource/mcp` — if any.
     */
    public function forMetadataPath(string $path): ?ProtectedResource;

    /**
     * The scopes the authorization server ITSELF accepts as a resource (UserInfo, the
     * decision endpoint): what the root `/.well-known/oauth-protected-resource` document
     * advertises.
     *
     * @return list<string>
     */
    public function issuerScopes(): array;
}
