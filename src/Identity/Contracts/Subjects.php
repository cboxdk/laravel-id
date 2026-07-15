<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\Identity\Exceptions\IdentityAlreadyLinked;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Identity\ValueObjects\Subject;

/**
 * The platform's single boundary to "who the user is". Everything else — sessions,
 * passkeys, MFA, memberships, SSO — references a subject only by its opaque
 * string id, so the platform never owns or assumes the host's user store.
 *
 * The package ships a default implementation over its own optional users table
 * (greenfield). To pull the platform into an existing app — including one with
 * several authenticatable models (users, admins, resellers) or a single model
 * with role flags — bind your own implementation to this contract
 * (config `cbox-id.subject.resolver`) and map ids to whatever model(s) you have.
 * Ids are opaque to the platform, so namespaced ids ("reseller:42") or globally
 * unique ids (ULID/UUID) both work.
 */
interface Subjects
{
    public function find(string $id): ?Subject;

    public function findByEmail(string $email): ?Subject;

    public function create(string $email, ?string $name = null, ?string $password = null): Subject;

    /**
     * Resolve the subject behind a federated identity. On first sight it creates
     * a new subject — but it NEVER merges into an existing account by email;
     * if the email already belongs to an account it throws
     * {@see AccountExistsForEmail}. Idempotent per
     * (provider, subject). Linking to an existing account is explicit — see
     * {@see link()}.
     *
     * @throws AccountExistsForEmail when the email already belongs to an account
     */
    public function provisionFederated(FederatedPrincipal $principal): Subject;

    /**
     * Explicitly link a provider identity to an ALREADY-authenticated subject —
     * the safe way to connect a second sign-in method, because the caller has
     * proven control of both sides (signed in as the subject, and just completed
     * the provider's auth). Throws
     * {@see IdentityAlreadyLinked} if the identity
     * belongs to a different subject.
     *
     * @throws IdentityAlreadyLinked when the identity is already linked to a different subject
     */
    public function link(string $subjectId, FederatedPrincipal $principal): void;

    /**
     * The external identities linked to a subject, as (provider, subject id)
     * pairs — for a "connected accounts" screen.
     *
     * @return array<int, array{provider: string, subject: string}>
     */
    public function linkedIdentities(string $subjectId): array;

    public function unlink(string $subjectId, string $provider): void;

    public function verifyPassword(string $subjectId, string $password): bool;

    public function setPassword(string $subjectId, string $password): void;

    /**
     * Store an ALREADY-HASHED credential verbatim — the migration/import path. The
     * hash is NOT re-hashed on the way in (that would destroy a foreign format),
     * so it must be a format a registered {@see HashVerifier} can verify. It is
     * transparently upgraded to the platform hasher on the subject's next
     * successful password login (lazy migration). Use {@see setPassword()} for a
     * plaintext password. A no-op for an unknown subject.
     */
    public function storeCredential(string $subjectId, string $passwordHash): void;

    /**
     * Whether the subject may authenticate right now. A resolver returns false
     * for accounts it considers disabled, deprovisioned, or locked. The platform
     * calls this at every login path to refuse a deactivated account a new
     * session (an unknown subject is treated as inactive). A host resolver maps
     * this to its own account-state model.
     */
    public function isActive(string $subjectId): bool;

    /**
     * Deactivate a subject: it can no longer authenticate. Existing sessions must
     * be revoked by the caller (or the resolver) separately. Idempotent; a no-op
     * for hosts that manage account state elsewhere.
     */
    public function deactivate(string $subjectId): void;

    /**
     * Re-enable a previously deactivated subject. Idempotent; a no-op for hosts
     * that manage account state elsewhere.
     */
    public function reactivate(string $subjectId): void;

    /**
     * Mark the subject's email address as verified (no-op if the current address
     * no longer matches $email — the confirmation is stale).
     */
    public function markEmailVerified(string $subjectId, string $email): void;
}
