<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

/**
 * Completes an OIDC principal from the provider's UserInfo endpoint, for the providers
 * whose `id_token` does not carry the person's address.
 *
 * Applies only to a connection whose catalogue entry says so
 * ({@see ProviderTemplate::$profileFromUserInfo}); for every other connection it returns
 * the principal unchanged and makes no request. Called AFTER the `id_token` has been
 * validated and its nonce checked, so the subject it completes is already proven.
 */
interface OidcUserInfo
{
    /**
     * @throws InvalidAssertion when the provider needs UserInfo and it cannot be read,
     *                          or when it describes a different subject than the token
     */
    public function complete(Connection $connection, FederatedPrincipal $principal, ?string $accessToken): FederatedPrincipal;
}
