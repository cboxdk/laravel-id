<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

/**
 * A verified environment-admin handoff: the PLATFORM-ROOT SUBJECT and the environment
 * the signed token binds together. Produced only by verifying a token the platform
 * itself minted, so it is proof that this identity was granted admin access to this
 * environment — the bridge that lets a control-plane identity administer a tenant
 * environment WITHOUT a second login and WITHOUT existing as a subject inside THAT
 * environment.
 *
 * The subject is the credential of record for account members, so it — not the account
 * membership row — is what the handoff carries and what the resulting admin session is
 * keyed on. The account membership (and with it the {@see AccountRole} capability gate)
 * is re-resolved from the subject on redemption and on every subsequent request, so a
 * membership revoked after the token was minted grants nothing.
 */
readonly class EnvironmentAdminGrant
{
    public function __construct(
        public string $subjectId,
        public string $environmentId,
    ) {}
}
