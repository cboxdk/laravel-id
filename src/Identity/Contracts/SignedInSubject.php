<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/**
 * Who is signed in to THIS browser, as the host application understands it.
 *
 * The package's own endpoints need this in exactly two places — RP-initiated logout and
 * the SAML IdP's plain-logout branch — and both used to ask `auth()->id()` directly. That
 * is a guess about the host: it assumes the application authenticates people through
 * Laravel's guard, and an application that keeps its own session (which any host with a
 * subject/operator/environment split does, because a guard models one identity and it has
 * three) answers null to it forever.
 *
 * The failure is silent and looks like success. `/oauth/logout` cleared the browser's own
 * session, returned 200 and redirected, so logout LOOKED fine — while
 * `revokeAllForUser()` never ran: sessions stayed Active, other devices stayed signed in,
 * and the person's own session list went on showing sessions they believed they had ended.
 * A relying party using this as global sign-out got success and no global sign-out.
 *
 * The default implementation still reads the guard, so a host that uses it sees no change.
 * A host that does not binds this to whatever it does use.
 */
interface SignedInSubject
{
    /**
     * The signed-in subject's id, or null when nobody is.
     *
     * MUST NOT fall back to a request parameter, an id_token hint, or anything else the
     * caller supplied — this answer decides whose sessions get destroyed, so it may only
     * come from what this browser has already proven.
     */
    public function id(): ?string;
}
