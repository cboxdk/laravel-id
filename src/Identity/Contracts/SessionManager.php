<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Models\Session;

interface SessionManager
{
    /**
     * @param  list<string>  $amr  how the user authenticated (e.g. ['pwd','mfa'])
     */
    public function start(
        string $userId,
        ?string $organizationId,
        array $amr,
        ?string $ip = null,
        ?string $userAgent = null,
    ): Session;

    /**
     * The session if it exists and is neither expired nor revoked, else null.
     */
    public function active(string $sessionId): ?Session;

    public function revoke(string $sessionId): void;

    public function revokeAllForUser(string $userId): void;
}
