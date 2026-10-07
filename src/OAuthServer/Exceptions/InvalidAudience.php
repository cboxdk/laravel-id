<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A token request whose scopes and `resource` cannot be reconciled with the registered
 * APIs. Carries the OAuth error code the token endpoint returns verbatim: `invalid_target`
 * (RFC 8707 §2) when the audience is missing or ambiguous, `invalid_scope` (RFC 6749 §5.2)
 * when nothing requested may be granted for the audience.
 */
class InvalidAudience extends RuntimeException
{
    public function __construct(public readonly string $error, string $message)
    {
        parent::__construct($message);
    }

    /**
     * @param  list<string>  $identifiers
     */
    public static function ambiguous(array $identifiers): self
    {
        return new self('invalid_target', sprintf(
            'The requested scopes belong to more than one API (%s). Name the one this token is for with the resource parameter.',
            implode(', ', $identifiers),
        ));
    }

    public static function nothingGrantable(): self
    {
        return new self('invalid_scope', 'None of the requested scopes may be granted to this client for the requested audience.');
    }

    /**
     * RFC 8707 §2: `resource` must be an absolute URI with no fragment. Refused rather than
     * dropped — a token issued unbound because its audience was unreadable would be
     * audienced to the issuer, which is a wider token than the client asked for.
     */
    public static function malformedResource(): self
    {
        return new self('invalid_target', 'The resource parameter must be an absolute URI with a host and no fragment.');
    }

    /**
     * More than one `resource` in one request.
     *
     * RFC 8707 §2 permits several, minting a token whose `aud` lists them all. Refused here
     * instead, on purpose: one token valid at two resource servers is a token either of
     * them can replay at the other, which is the confused-deputy hole audience binding
     * exists to close. A client that needs two audiences asks twice — a refresh token or a
     * token exchange per resource — and each token is good in exactly one place.
     */
    public static function multipleResources(): self
    {
        return new self('invalid_target', 'Only one resource may be requested per token. Request a separate token for each resource server.');
    }

    /**
     * A `resource` this environment does not serve — not a registered API, not a resource
     * the host declared, not the issuer — asked for by a client that may only be audienced
     * to resources that are.
     */
    public static function unknownResource(string $resource): self
    {
        return new self('invalid_target', "The resource [{$resource}] is not served by this authorization server.");
    }

    /**
     * A declared protected resource that does not accept self-registered clients, asked
     * for by one (RFC 7591 registration or a client ID metadata document).
     */
    public static function notOfferedToDynamicClients(string $resource): self
    {
        return new self('invalid_target', "The resource [{$resource}] does not accept dynamically registered clients.");
    }

    /**
     * A refresh request naming a different audience than the grant it refreshes. RFC 8707
     * §2.2 lets a server keep a refresh token bound to its original resource, and this one
     * does: the person consented to one audience, and a refresh is not a fresh consent.
     */
    public static function boundToAnotherResource(): self
    {
        return new self('invalid_target', 'This refresh token is bound to a different resource than the one requested.');
    }
}
