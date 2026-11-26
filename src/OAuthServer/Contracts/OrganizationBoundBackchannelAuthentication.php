<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\BackchannelAuthenticationResult;

/** Optional capability: old BackchannelAuthentication implementations remain valid. */
interface OrganizationBoundBackchannelAuthentication extends BackchannelAuthentication
{
    /** @param list<string> $scopes */
    public function requestForOrganization(
        Client $client,
        array $scopes,
        string $loginHint,
        string $organizationId,
        ?string $bindingMessage = null,
        ?string $nonce = null,
        ?int $requestedExpiry = null,
        ?string $resource = null,
    ): BackchannelAuthenticationResult;
}
