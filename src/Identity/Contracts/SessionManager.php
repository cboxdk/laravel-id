<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\Identity\Models\Session;

/**
 * Sessions are the platform's record of an authenticated user. `start()` is the one
 * primitive every login path funnels through — password, magic link, SSO, CIBA — which
 * is why the {@see HookPoint::PostLogin} inline hook fires there and can refuse a login
 * the platform itself has already accepted.
 */
interface SessionManager
{
    /**
     * @param  list<string>  $amr  how the user authenticated (e.g. ['pwd','mfa'])
     *
     * @throws ActionDenied when a {@see HookPoint::PostLogin} hook vetoes the login —
     *                      no session is created
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
