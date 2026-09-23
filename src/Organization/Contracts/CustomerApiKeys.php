<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\Organization\Enums\ApiKeyRefusal;
use Cbox\Id\Organization\Exceptions\CustomerApiKeyRefused;
use Cbox\Id\Organization\Exceptions\InvalidApiKeyPrefix;
use Cbox\Id\Organization\Models\CustomerApiKey;
use Cbox\Id\Organization\ValueObjects\ApiKeyActor;
use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;
use Cbox\Id\Organization\ValueObjects\ApiKeyVerification;
use Cbox\Id\Organization\ValueObjects\IssuedCustomerApiKey;
use Cbox\Id\Organization\ValueObjects\NewCustomerApiKey;
use Illuminate\Database\Eloquent\Collection;

/**
 * Customer API keys: an end-customer of an app built on this platform mints a key for
 * THAT app's API, and the app verifies it with its own client credentials.
 *
 * A key is bound to one app (`client_id`), one organization and one holder, and carries
 * a subset of the app's permissions. The subset is checked against the holder's current
 * permissions at issuance and re-applied at every verification, so a key never outlives
 * or out-ranks the access of the person it belongs to.
 *
 * Everything here runs inside the ambient environment: a key, its app and its holder
 * are all environment-scoped, and nothing crosses.
 */
interface CustomerApiKeys
{
    /**
     * Declare (or clear, with null) the prefix an app's keys carry. Declaring one is how
     * an app opts in: a client without a prefix issues no keys. Clearing it stops new
     * issuance only — keys already issued keep verifying until revoked, and keep the
     * prefix they were minted with.
     *
     * @throws InvalidApiKeyPrefix when another app in the environment declared it already
     * @throws CustomerApiKeyRefused when no such client exists ({@see ApiKeyRefusal::UnknownClient})
     */
    public function setPrefix(string $clientId, ?ApiKeyPrefix $prefix): void;

    /**
     * Issue a key. Refused unless the app has a prefix, the holder is an active member
     * of an active organization, and every requested permission is one the holder
     * currently holds for the app.
     *
     * `$actor` is who issued it, for the audit trail; null means the holder themself.
     *
     * @throws CustomerApiKeyRefused
     */
    public function issue(NewCustomerApiKey $input, ?ApiKeyActor $actor = null): IssuedCustomerApiKey;

    /**
     * Verify a presented key on behalf of the authenticated app `$caller`. Active only
     * when the key is bound to that app, live, and its holder still an active member of
     * an active organization with an active account. Every other outcome — including a
     * key that belongs to a different app — is the same {@see ApiKeyVerification::inactive()}.
     *
     * Stamps `last_used_at`, at most once a minute per key.
     */
    public function verify(Client $caller, string $plaintext): ApiKeyVerification;

    /** A key by id, within the environment. Null when there is none. */
    public function find(string $keyId): ?CustomerApiKey;

    /**
     * Revoke a key. Idempotent: returns false when there was no live key to revoke.
     * Authorization — may THIS actor revoke THAT key — is the caller's decision.
     */
    public function revoke(string $keyId, ApiKeyActor $actor): bool;

    /**
     * A holder's keys in an organization, newest first, optionally for one app only.
     * Revoked and expired keys are included; filter on {@see CustomerApiKey::isActive()}.
     *
     * @return Collection<int, CustomerApiKey>
     */
    public function forUser(string $organizationId, string $userId, ?string $clientId = null): Collection;

    /**
     * Every key in an organization, newest first, optionally for one app only.
     *
     * @return Collection<int, CustomerApiKey>
     */
    public function forOrganization(string $organizationId, ?string $clientId = null): Collection;
}
