<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/**
 * Which {@see SessionManager} session THIS browser holds, as the host application
 * understands it.
 *
 * The companion to {@see SignedInSubject}, needed in one place: RP-initiated logout
 * without a verifiable `id_token_hint`. That request may only sign out this browser, and
 * the package used to do exactly that at the Laravel-session level and no further — the
 * session row stayed active until it expired, so the applications it had signed the
 * person in to were never told the person had left.
 *
 * The default answers null, because the package cannot know where a host keeps the id.
 * A host that stores it (in its own session, a cookie, a guard) binds this and RP-initiated
 * logout then ends that session properly.
 */
interface SignedInSession
{
    /**
     * The id of the session this browser holds, or null when there is none or the host
     * does not say.
     *
     * MUST come only from what this browser has already proven — never from a request
     * parameter — because the answer decides which session is ended.
     */
    public function id(): ?string;
}
