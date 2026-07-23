<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Identity\ValueObjects\LinkedIdentity;
use Cbox\Id\Identity\ValueObjects\Subject;

/**
 * A host-style {@see Subjects} resolver backed by an in-memory store — stands in
 * for an app that resolves subjects from its own user model(s). Proves the
 * platform never touches its own users table when a resolver is bound.
 */
final class ArraySubjects implements Subjects
{
    /** @var array<string, Subject> */
    private array $byId = [];

    /** @var array<string, string> email => id */
    private array $emailIndex = [];

    private int $sequence = 0;

    public function find(string $id): ?Subject
    {
        return $this->byId[$id] ?? null;
    }

    public function findMany(array $ids): array
    {
        $subjects = [];

        foreach (array_unique($ids) as $id) {
            if (isset($this->byId[$id])) {
                $subjects[$id] = $this->byId[$id];
            }
        }

        return $subjects;
    }

    public function findByEmail(string $email): ?Subject
    {
        $id = $this->emailIndex[$email] ?? null;

        return $id === null ? null : ($this->byId[$id] ?? null);
    }

    public function create(string $email, ?string $name = null, ?string $password = null): Subject
    {
        // A host might key subjects by type — e.g. "reseller:42". The platform
        // treats the whole thing as opaque.
        $subject = new Subject('reseller:'.(++$this->sequence), $email, $name);

        $this->byId[$subject->id] = $subject;
        $this->emailIndex[$email] = $subject->id;

        return $subject;
    }

    public function provisionFederated(FederatedPrincipal $principal): Subject
    {
        $email = $principal->email ?? $principal->subject.'@federated';

        return $this->findByEmail($email) ?? $this->create($email, $principal->name);
    }

    public function link(string $subjectId, FederatedPrincipal $principal): void {}

    /**
     * @return array<int, array{provider: string, subject: string}>
     */
    /**
     * @return list<LinkedIdentity>
     */
    public function linkedIdentities(string $subjectId): array
    {
        return [];
    }

    public function unlink(string $subjectId, string $provider): void {}

    public function verifyPassword(string $subjectId, string $password): bool
    {
        return false;
    }

    public function setPassword(string $subjectId, string $password): void
    {
        // No-op: this host delegates credentials elsewhere.
    }

    public function storeCredential(string $subjectId, string $passwordHash): void
    {
        // No-op: this host owns its credential store; import targets the default.
    }

    public function isActive(string $subjectId): bool
    {
        // This host tracks account state elsewhere; everything it resolves is live.
        return isset($this->byId[$subjectId]);
    }

    public function deactivate(string $subjectId): void
    {
        // No-op: this host manages account lifecycle in its own store.
    }

    public function reactivate(string $subjectId): void
    {
        // No-op: this host manages account lifecycle in its own store.
    }

    public function markEmailVerified(string $subjectId, string $email): void
    {
        // No-op: this host tracks verification elsewhere.
    }
}
