<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;

/**
 * An authenticated identity, as the platform sees it: an opaque string id plus
 * the couple of attributes the platform needs (email/name for tokens and
 * notifications). It is deliberately NOT a host model — the platform references
 * subjects only by their opaque id, so it integrates with any user store: a
 * single users table, an existing app's model, or several authenticatable
 * models (users, admins, resellers) behind one {@see Subjects}
 * resolver.
 */
readonly class Subject
{
    /**
     * @param  UserStatus|null  $status  whether this account may authenticate, WHEN THE
     *                                   RESOLVER SAID. Null means it did not — see
     *                                   {@see admitsSignIn()}.
     */
    public function __construct(
        public string $id,
        public ?string $email = null,
        public ?string $name = null,
        public bool $emailVerified = false,
        public ?UserStatus $status = null,
    ) {}

    /**
     * Whether this subject may authenticate right now, or null when the resolver that
     * produced it did not say.
     *
     * {@see Subjects::find()} deliberately returns a deactivated account — callers need to
     * render one — so every authenticated request re-asks {@see Subjects::isActive()},
     * and against the default store that was a SECOND `select * from users where id = ?`
     * for a row the caller was already holding. Carrying the status makes the answer free
     * for a resolver that knows it.
     *
     * NULL RATHER THAN A DEFAULT OF ACTIVE, and that is the whole safety of this. A host
     * app binds its own {@see Subjects} resolver and constructs these itself; one written
     * before this field existed says nothing about status, and defaulting to Active would
     * silently turn its deactivated accounts into signed-in ones. Null means "ask", so a
     * resolver that has not been updated keeps paying the query and keeps being right.
     */
    public function admitsSignIn(): ?bool
    {
        return $this->status === null ? null : $this->status === UserStatus::Active;
    }
}
