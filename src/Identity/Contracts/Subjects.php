<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

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
     * Resolve the subject behind a federated identity, creating the subject
     * and/or link on first sight. Idempotent per (provider, subject).
     */
    public function provisionFederated(FederatedPrincipal $principal): Subject;

    public function verifyPassword(string $subjectId, string $password): bool;

    public function setPassword(string $subjectId, string $password): void;
}
