<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\CibaAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\CibaAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\CibaExpired;
use Cbox\Id\OAuthServer\Exceptions\CibaSlowDown;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Exceptions\UnknownUserHint;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Cbox\Id\OAuthServer\ValueObjects\BackchannelAuthenticationResult;

/**
 * OpenID Connect Client-Initiated Backchannel Authentication (CIBA), poll mode.
 *
 * A client (typically an autonomous / AI agent) initiates authentication on a
 * decoupled device: it names the user via `login_hint`, the user approves
 * out-of-band on their own authentication device, and the client polls the token
 * endpoint until approval. This is the human-in-the-loop approval primitive for
 * high-risk agent actions.
 *
 * The interactive notification + approval surface is the HOST's responsibility
 * (as with the OAuth consent screen): {@see request()} persists the pending
 * request and emits a domain event; the host notifies the user and, on their
 * decision, calls {@see approve()} / {@see deny()}.
 */
interface BackchannelAuthentication
{
    /**
     * Begin a CIBA flow: resolve the user from `loginHint`, persist a pending
     * request, emit `oauth.backchannel_authentication_requested`, and return the
     * client's polling handle. `requestedExpiry` is clamped to the configured
     * ceiling.
     *
     * @param  list<string>  $scopes
     *
     * @throws UnknownUserHint when the login_hint resolves to no user
     */
    public function request(
        Client $client,
        array $scopes,
        string $loginHint,
        ?string $bindingMessage = null,
        ?string $nonce = null,
        ?int $requestedExpiry = null,
    ): BackchannelAuthenticationResult;

    /**
     * Approve a pending request by its INTERNAL id (from the host's approval
     * surface, never the client's auth_req_id), optionally binding an organization
     * context.
     *
     * `$subjectId` is the subject DOING the approving, and must match the user the
     * request was raised for: approval is the consent step for an agent acting on
     * that user's behalf, and the redeemed token is minted for them. It is required
     * rather than derived from ambient auth so a host cannot forget to bind it.
     *
     * Returns false if the request is unknown, expired, not pending, or belongs to
     * a different subject.
     */
    public function approve(string $requestId, string $subjectId, ?string $organizationId = null): bool;

    /**
     * Deny a pending request by its internal id, acting as `$subjectId`. Returns
     * false if unknown/expired or the request belongs to a different subject.
     */
    public function deny(string $requestId, string $subjectId): bool;

    /**
     * Poll for the token (CIBA poll mode). Returns the approved grant, or throws.
     *
     * @throws CibaAuthorizationPending while the user has not yet approved
     * @throws CibaSlowDown when polling faster than the interval
     * @throws CibaAccessDenied when the user denied the request
     * @throws CibaExpired when the auth_req_id has expired
     * @throws InvalidGrant for an unknown or already-redeemed auth_req_id
     */
    public function redeem(string $clientId, string $authReqId): AuthorizedGrant;
}
