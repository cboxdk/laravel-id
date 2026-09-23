<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/**
 * Told when a person's sign-in session ends, so the applications it signed them in to
 * can end theirs too.
 *
 * Identity owns the session and not the relying parties it was used at — OAuthServer
 * owns those, and already depends on Identity. So Identity declares what it needs here
 * and OAuthServer supplies it (Back-Channel Logout), the same one-way arrangement as
 * {@see SubjectGrantRevoker}.
 *
 * {@see SessionManager} calls it on every revocation, which is what makes the common
 * paths — sign out, "sign out everywhere", an administrator ending a session, a password
 * reset, a deprovisioned account — reach the applications without each caller having to
 * remember. A host that ends sessions some other way calls it itself.
 *
 * Implementations MUST NOT make a network call on the calling thread: this runs inside a
 * sign-out request, and a relying party that is down must not make signing out slow.
 */
interface LogoutPropagator
{
    /**
     * One sign-in session has ended: notify every application it signed the person in to.
     */
    public function sessionEnded(string $sessionId): void;

    /**
     * Every session this person holds has ended: notify every application any of them
     * signed the person in to.
     */
    public function subjectSignedOut(string $userId): void;
}
