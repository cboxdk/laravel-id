<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;

/**
 * Whether a SELF-REGISTERED client (RFC 7591) may use a decoupled grant — CIBA or the
 * device grant — for the resource its request names.
 *
 * Registration only says what a client may ask for. These grants put a prompt in front
 * of a person from a request with no browser bound to the flow, so the decision is made
 * again on every request, against the one resource it names (RFC 8707 `resource`):
 *
 *  - a resource is REQUIRED — a self-registered client's token is always for a resource
 *    that opened itself to such clients, never the issuer at large;
 *  - that resource must have opened this grant (`dynamic_client_grants`);
 *  - a PUBLIC client may start CIBA only where the resource also set
 *    `dynamic_public_backchannel`.
 *
 * An operator-registered client is not this class's business: it answers null and the
 * usual rules apply.
 */
final readonly class DynamicGrantPolicy
{
    public function __construct(private ProtectedResources $resources) {}

    public static function applies(Client $client): bool
    {
        return $client->isDynamicallyRegistered();
    }

    /**
     * The resource a self-registered client may use $grant for, or null when the client is
     * not self-registered.
     *
     * @throws InvalidAudience `invalid_target` when the request may not go ahead
     */
    public function resourceFor(Client $client, string $grant, ?string $resource): ?ProtectedResource
    {
        if (! self::applies($client)) {
            return null;
        }

        if ($resource === null) {
            throw new InvalidAudience('invalid_target', 'a self-registered client must name the protected resource (RFC 8707 resource) it asks for');
        }

        $declared = $this->resources->find($resource);

        if ($declared === null || ! $declared->allowsDynamicGrant($grant)) {
            throw new InvalidAudience('invalid_target', 'this resource does not let self-registered clients use this grant');
        }

        if ($grant === 'urn:openid:params:grant-type:ciba'
            && $client->type === ClientType::Public
            && ! $declared->dynamicPublicBackchannel) {
            throw new InvalidAudience('invalid_target', 'this resource lets self-registered clients use CIBA only with private_key_jwt');
        }

        return $declared;
    }
}
