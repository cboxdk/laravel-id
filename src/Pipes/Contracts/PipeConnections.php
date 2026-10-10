<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Contracts;

use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Pipes\Exceptions\PipeConnectFailed;
use Cbox\Id\Pipes\Exceptions\PipeConnectionNotFound;
use Cbox\Id\Pipes\Exceptions\PipeNotFound;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\ValueObjects\PipeAuthorization;
use Cbox\Id\Pipes\ValueObjects\PipeConnectState;

/**
 * A signed-in person connecting, listing and disconnecting their own third-party
 * accounts.
 *
 * The host owns the browser: it calls {@see start()} for the person who is signed in,
 * keeps the returned state in THEIR session, redirects, and hands the stashed state back to
 * {@see complete()} on the callback. The tokens land sealed in the token vault, owned by
 * the person, and never pass back through this contract.
 */
interface PipeConnections
{
    /**
     * Begin connecting `$userId`'s account at the environment's pipe for `$provider`.
     *
     * @throws PipeNotFound when the environment has no enabled pipe for the provider
     */
    public function start(string $provider, string $userId, string $redirectUri): PipeAuthorization;

    /**
     * Finish a connect flow: check `$state` against what the host stashed, exchange the
     * code (with the PKCE verifier), store the tokens in the vault and record the
     * connection. Connecting again replaces the tokens of an existing connection — which is
     * how a `needs_reauth` connection becomes `active`.
     *
     * @throws PipeConnectFailed with a stable reason code
     */
    public function complete(PipeConnectState $flow, string $state, string $code): PipeConnection;

    /**
     * Disconnect: revoke at the provider where it supports that, revoke the tokens in the
     * vault, and forget the connection. With `$userId`, the connection must be that
     * person's — another person's answers exactly like a missing one. The audit actor is
     * `$actor` when given (an administrator, a key), else the person, else the system.
     *
     * @return bool whether the provider confirmed the revocation
     *
     * @throws PipeConnectionNotFound
     */
    public function disconnect(string $connectionId, ?string $userId = null, ?AuditActor $actor = null): bool;

    public function find(string $connectionId, ?string $userId = null): ?PipeConnection;

    /** @return list<PipeConnection> */
    public function forUser(string $userId): array;

    /** @return list<PipeConnection> */
    public function forPipe(string $pipeId): array;
}
