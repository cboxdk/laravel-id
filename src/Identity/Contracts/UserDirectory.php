<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

interface UserDirectory
{
    public function find(string $id): ?User;

    public function findByEmail(string $email): ?User;

    public function create(string $email, ?string $name = null, ?string $password = null): User;

    /**
     * Find the user behind a federated identity, creating the user and/or link
     * on first sight. Idempotent per (provider, subject).
     */
    public function provisionFederated(FederatedPrincipal $principal): User;

    public function verifyPassword(User $user, string $password): bool;

    public function setPassword(User $user, string $password): void;
}
