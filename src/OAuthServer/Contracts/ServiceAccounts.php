<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\UnknownServiceAccount;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;

interface ServiceAccounts
{
    /**
     * Create an M2M service account (a confidential client). The secret is
     * revealed once in the returned value.
     *
     * @param  list<string>  $scopes
     */
    public function create(string $organizationId, string $name, array $scopes = []): RegisteredClient;

    /**
     * Overlap-rotate a service account: mint a *successor* credential with the
     * same privileges (org, name, scopes) while the current one stays valid, so a
     * consumer can cut over with zero downtime. The old account is retired
     * separately, only after the successor is confirmed working ({@see retire}).
     * Returns the new credential (secret revealed once).
     *
     * @throws UnknownServiceAccount
     */
    public function rotate(string $clientId): RegisteredClient;

    /**
     * Retire a service account once its successor has taken over: it can mint no
     * further tokens (its client is removed) and every outstanding access token
     * it issued is revoked. Idempotent for an already-retired account.
     *
     * @throws UnknownServiceAccount
     */
    public function retire(string $clientId): void;
}
