<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Validators\OidcAssertionValidator;

/**
 * Whether an OIDC connection may carry its provider's "this address is verified" through.
 *
 * Only when the provider says so explicitly AND the address is in a domain the
 * connection's own organization has proven. A connection is configured by a CUSTOMER:
 * they choose the issuer, so they can point one at an IdP they run and assert anything,
 * including `email: ceo@somebody-else.com, email_verified: true`. Carrying that through
 * unconditionally would let any tenant mint a verified address in another company's
 * domain — and a verified address is precisely what a relying party downstream uses to
 * decide two accounts are the same person.
 *
 * Domain verification is the boundary this platform already uses to decide an
 * organization speaks for a domain (it is what routes home-realm sign-in), so it is the
 * right one here: an organization that has proven `corp.com` may vouch for
 * `dana@corp.com`, and for nothing else.
 *
 * Lifted out of {@see OidcAssertionValidator} so the UserInfo path — where Intuit says
 * `emailVerified` rather than in the token — applies the identical rule instead of a
 * second copy that could drift from it.
 */
class OrganizationVouchedEmail
{
    public function __construct(private readonly DomainVerification $domains) {}

    /**
     * True, or null — never false. Null leaves the address unverified, the state it
     * would have been in anyway; false would be a claim we then store.
     */
    public function verified(Connection $connection, ?string $email, mixed $providerSays): ?bool
    {
        if ($providerSays !== true || $email === null || $email === '') {
            return null;
        }

        $organizationId = $connection->organization_id;
        $verified = $this->domains->forEmail($email);

        // An empty owner vouches for nothing — the same rule every ownership check in
        // this codebase states, for the same reason. Kept exactly as the validator has
        // always had it, including for a connection the environment owns.
        return $organizationId !== '' && $verified?->organization_id === $organizationId ? true : null;
    }
}
