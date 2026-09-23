<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Support\SessionIdentifier;

/**
 * Everything an ID Token is minted from, independent of which grant produced it.
 *
 * WHY THIS EXISTS. The token endpoint minted ID Tokens straight from an
 * {@see AuthorizedGrant}, so only the authorization-code (and device/CIBA) paths
 * could produce one and a refresh could not — it returned an access token and a
 * refresh token and nothing else. For a relying party that authenticates the
 * ACCESS token that is merely tidy; for one that authenticates the ID TOKEN it
 * means the credential it actually presents cannot be renewed at all, so a short
 * lifetime becomes a browser window at every expiry. Kubernetes is exactly that
 * relying party: `kubectl oidc-login` presents the ID Token.
 *
 * Naming the inputs once, here, is what lets both paths mint the same token from
 * the same rules — rather than a second, subtly different builder growing beside
 * the first.
 */
readonly class IdTokenGrant
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?string $nonce = null,
        public ?int $authTime = null,
        public array $amr = [],

        /**
         * The sign-in session behind this identity, or null when none was recorded. The
         * ID Token carries it as `sid` — derived, never the raw id; see {@see sid()}.
         */
        public ?string $sessionId = null,
    ) {}

    /**
     * The OIDC `sid` for this grant's session (Back-Channel Logout 1.0 §2.1), or null.
     */
    public function sid(): ?string
    {
        return $this->sessionId !== null && $this->sessionId !== ''
            ? SessionIdentifier::sid($this->sessionId)
            : null;
    }

    public static function fromAuthorization(AuthorizedGrant $grant): self
    {
        return new self(
            userId: $grant->userId,
            organizationId: $grant->organizationId,
            scopes: $grant->scopes,
            nonce: $grant->nonce,
            authTime: $grant->authTime,
            amr: $grant->amr,
            sessionId: $grant->sessionId,
        );
    }

    /**
     * The same subject, seen through a refresh.
     *
     * NULL WHEN THERE IS NO USER. `client_credentials` refreshes exist and have
     * no subject to assert; an ID Token describes an authenticated person, and
     * one minted for a machine grant would be an assertion about nobody.
     *
     * NO NONCE, deliberately. A nonce binds an ID Token to one authentication
     * REQUEST so a relying party can detect replay, and a refresh is not an
     * authentication request. Echoing the original would hand back a token the
     * client has already seen that nonce on — which is precisely the condition
     * its replay check exists to catch.
     *
     * `auth_time` and `amr` DO carry over, because they describe the login the
     * family descends from (OIDC Core §12.2). Dropping them would let a session's
     * asserted assurance level fall at its first refresh, which reads to a
     * relying party gating on `acr` as the user losing their second factor.
     */
    public static function fromRefresh(RefreshGrant $grant): ?self
    {
        if ($grant->userId === null) {
            return null;
        }

        return new self(
            userId: $grant->userId,
            organizationId: $grant->organizationId,
            scopes: $grant->scopes,
            nonce: null,
            authTime: $grant->authTime,
            amr: $grant->amr,
            // `sid` DOES carry over: the refreshed token describes the same sign-in
            // session, and a relying party that matched the first one's `sid` to its own
            // session must find the same value on the next.
            sessionId: $grant->sessionId,
        );
    }
}
