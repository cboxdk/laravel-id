<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ConnectedApplication;
use Cbox\Id\OAuthServer\ValueObjects\RefreshGrant;

interface RefreshTokens
{
    /**
     * Issue the first refresh token of a new rotation family for this grant.
     * Returns the raw token (only its hash is stored). When `$dpopJkt` is given
     * (RFC 9449 §5), the token is bound to that DPoP key thumbprint and rotation
     * will require a proof of the same key.
     *
     * `$authTime` and `$amr` describe the login this family descends from, and
     * are recorded so a refreshed ID Token can still describe THAT
     * authentication (OIDC Core §12.2) rather than the moment it was refreshed.
     * `$sessionId` is the sign-in session it came from, for the same reason: a refreshed
     * ID Token keeps the `sid` of the first.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $amr
     */
    public function issue(Client $client, ?string $userId, ?string $organizationId, array $scopes, ?string $audience = null, ?string $dpopJkt = null, ?int $authTime = null, array $amr = [], ?string $sessionId = null): string;

    /**
     * Rotate a presented refresh token: validate it, consume it, and mint its
     * successor in the same family. Presenting an already-consumed token is
     * treated as theft — the whole family is revoked and {@see InvalidGrant} is
     * thrown. Throws {@see InvalidGrant} for unknown/expired/revoked tokens, a
     * client mismatch, or — for a DPoP-bound token — a missing or mismatched
     * proof key (`$presentedJkt`).
     *
     * @throws InvalidGrant
     */
    public function rotate(string $clientId, string $rawToken, ?string $presentedJkt = null): RefreshGrant;

    /**
     * Revoke every refresh token in the family a given raw token belongs to
     * (e.g. on logout). No-op if the token is unknown. When `$clientId` is given
     * (RFC 7009 §2.1), the family is revoked only if the token was issued to that
     * client — a client can't revoke another client's tokens.
     */
    public function revoke(string $rawToken, ?string $clientId = null): void;

    /**
     * Revoke every active refresh token a user holds, optionally scoped to one
     * organization. The freshness lever for the federated-RBAC model: when a role
     * or permission changes, revoke the user's refresh tokens so their next refresh
     * forces re-authentication and re-mints a token with the new claims, instead of
     * riding a stale grant until it expires. Returns the number revoked.
     *
     * NO APPLICATION IS SIGNED OUT. This is a claims-freshness lever, called on every role
     * assignment and unassignment: the person is still who they were and still belongs
     * where they did, so their application sessions stay up and the next refresh (or
     * sign-in) carries the new roles. Telling every application to end its session here
     * would sign people out of everything whenever an administrator adjusted a role.
     * When the person's access is actually OVER, call {@see withdrawAccess()}.
     */
    public function revokeForUser(string $userId, ?string $organizationId = null): int;

    /**
     * The person's access is over — deactivated, removed from the organization — so revoke
     * their refresh tokens (optionally only in one organization) AND tell the applications
     * that held them to end the sessions they keep for the person (OIDC Back-Channel
     * Logout). A revoked grant behind a live application session is the half of
     * revocation the person cannot see. Returns the number of refresh tokens revoked.
     *
     * The applications are told even when no refresh token was live: a client that never
     * asked for `offline_access` holds none and still signed the person in.
     */
    public function withdrawAccess(string $userId, ?string $organizationId = null): int;

    /**
     * Every application this person has a live grant to, one row per client.
     *
     * FOR THE PERSON, NOT FOR AN OPERATOR. Rotation mints a refresh-token row on every
     * use, so the rows describe freshness rather than consent — showing them would offer
     * somebody eleven identical entries for one approval. This collapses them to the fact
     * a person can act on: which applications can act as me, what they may do, and when
     * they last did.
     *
     * @return list<ConnectedApplication>
     */
    public function connectedApplications(string $userId): array;

    /**
     * Withdraw one application's access, leaving every other grant alone.
     *
     * The whole point of showing somebody their connected applications is that they can
     * remove ONE — `withdrawAccess()` signs them out of everything, which is the right
     * answer to "my account is compromised" and the wrong answer to "I do not use that
     * CLI any more". That one application is told to end its sessions for the user
     * (OIDC Back-Channel Logout); no other is.
     *
     * @return int how many live grants were withdrawn
     */
    public function revokeForUserAndClient(string $userId, string $clientId): int;
}
