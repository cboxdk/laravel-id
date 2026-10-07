<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use InvalidArgumentException;

/**
 * A protected resource the host declared (`cbox-id.oauth.protected_resources`, or a
 * rebound {@see ProtectedResources}) cannot be served as
 * described. Thrown when the declaration is read, so a typo fails the first request that
 * needs it — loudly, with the field named — instead of quietly minting tokens for an
 * audience no resource server will ever recognise.
 */
class InvalidProtectedResource extends InvalidArgumentException
{
    public static function identifier(string $identifier): self
    {
        return new self("The protected resource identifier [{$identifier}] must be an absolute https URI (http only on a loopback host) with no query, fragment or credentials, at most 255 characters.");
    }

    public static function missingIdentifier(): self
    {
        return new self('A protected resource needs either an absolute `identifier` or a `path` joined to the issuer.');
    }

    public static function scope(string $scope): self
    {
        return new self("The scope [{$scope}] is not a valid scope token (RFC 6749 §3.3: printable ASCII, no spaces, quotes or backslashes, at most 128 characters).");
    }

    public static function protocolScope(string $scope): self
    {
        return new self("The scope [{$scope}] is defined by the authorization server itself and cannot belong to a protected resource.");
    }
}
