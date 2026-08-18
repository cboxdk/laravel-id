<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/**
 * Revokes the long-lived API grants a subject holds, so a credential change can cut
 * access that outlives an interactive session.
 *
 * Identity owns the credential but not the grant model, and OAuthServer already depends
 * on Identity — so Identity declares what it needs here and OAuthServer supplies it,
 * keeping the dependency one-way instead of making the two modules circular.
 */
interface SubjectGrantRevoker
{
    /**
     * Revoke every outstanding grant held by the subject — refresh tokens AND the access
     * tokens already in flight. A no-op when they hold none.
     *
     * BOTH HALVES, because for a while it was only the first. Revoking refresh tokens
     * stops the renewal and leaves every access token already issued alive until it
     * expires: a leaver kept working at UserInfo and at the frontend session endpoint for
     * the rest of that token's life. Worse, RFC 8693 token exchange took a live access
     * token and minted a fresh one, so "the rest of its life" renewed itself for as long
     * as the holder cared to keep asking.
     */
    public function revokeGrantsForUser(string $userId): void;
}
