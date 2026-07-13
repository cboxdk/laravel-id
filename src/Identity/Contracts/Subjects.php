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
     */
    public function provisionFederated(FederatedPrincipal $principal): Subject;

    /**
     * Explicitly link a provider identity to an ALREADY-authenticated subject —
     * the safe way to connect a second sign-in method, because the caller has
     * proven control of both sides (signed in as the subject, and just completed
     * the provider's auth). Throws
     * {@see IdentityAlreadyLinked} if the identity
     * belongs to a different subject.
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
     * Mark the subject's email address as verified (no-op if the current address
     * no longer matches $email — the confirmation is stale).
     */
    public function markEmailVerified(string $subjectId, string $email): void;
}
