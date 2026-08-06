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
     * Revoke every outstanding refresh-token grant held by the subject. A no-op when
     * they hold none.
     */
    public function revokeGrantsForUser(string $userId): void;
}
