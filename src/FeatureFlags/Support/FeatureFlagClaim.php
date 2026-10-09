<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Support;

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;

/**
 * The `feature_flags` claim: the keys of every flag that is on for the token's subject in
 * its organization, sorted.
 *
 * One rule, read by all three places that carry it — the access token, the ID token and
 * UserInfo — so they cannot disagree about when it appears:
 *
 *  - only when the grant holds the `feature_flags` scope. Without it the claim is absent,
 *    so no existing client's token changes shape;
 *  - with the scope it is ALWAYS present, as an empty list when nothing is on. An app
 *    that asked can then tell "no flags are on" from "this token does not say";
 *  - a machine token (`client_credentials`) has no user, so it is evaluated for its
 *    organization alone.
 *
 * Tokens carry the flags as they were when minted; a refresh re-reads them and UserInfo
 * reads them live, the same freshness `org_role` has.
 */
final readonly class FeatureFlagClaim
{
    public const CLAIM = 'feature_flags';

    public function __construct(private FeatureFlags $flags) {}

    /**
     * The claim's value for a grant, or null when the grant did not ask for it.
     *
     * @param  list<string>  $scopes  the GRANTED scopes
     * @return list<string>|null
     */
    public function for(array $scopes, ?string $userId, ?string $organizationId): ?array
    {
        if (! in_array(ProtocolScope::FeatureFlags->value, $scopes, true)) {
            return null;
        }

        return $this->flags->forSubject($userId, $organizationId);
    }
}
