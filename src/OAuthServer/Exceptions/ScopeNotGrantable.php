<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use Cbox\Id\OAuthServer\ValueObjects\RegisteredScope;
use InvalidArgumentException;

/**
 * A client was about to be given registered API scopes its owner may not hold.
 *
 * Thrown when a client is SAVED — by the registry, by dynamic registration, or by a host
 * writing `scopes` on the model directly — so the free-text scope field can no longer be
 * used to claim another API's authority. The token endpoint applies the same rule again at
 * issuance for rows that predate the API's registration.
 *
 * {@see RegisteredScope::mayBeHeldBy()} is the rule.
 */
class ScopeNotGrantable extends InvalidArgumentException
{
    /**
     * @param  list<string>  $scopes  the refused scope keys
     */
    public function __construct(public readonly array $scopes, string $message)
    {
        parent::__construct($message);
    }

    /**
     * @param  list<string>  $scopes
     */
    public static function forScopes(array $scopes): self
    {
        return new self($scopes, sprintf(
            'The scope(s) %s belong to a registered API this client may not hold. A client '
            .'owned by an organization can hold scopes of its own organization\'s APIs, and the '
            .'tenant-requestable scopes of environment-owned APIs.',
            implode(' ', $scopes),
        ));
    }
}
