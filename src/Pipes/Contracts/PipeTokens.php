<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Contracts;

use Cbox\Id\Pipes\Exceptions\PipeConnectionMissing;
use Cbox\Id\Pipes\Exceptions\PipeConnectionNotFound;
use Cbox\Id\Pipes\Exceptions\PipeLeaseDenied;
use Cbox\Id\Pipes\Exceptions\PipeReauthorizationRequired;
use Cbox\Id\Pipes\Exceptions\PipeRefreshFailed;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\ValueObjects\PipeAccessToken;

/**
 * Fresh access tokens for authorised apps, and the refresh that keeps them fresh.
 */
interface PipeTokens
{
    /**
     * Lease a working access token for `$userId`'s connection at `$provider` to the app
     * `$clientId`. Refreshes first when the token is expired or about to be.
     *
     * Deny-by-default and audited: an app that is not granted the pipe (or a pipe that does
     * not exist, or is disabled) is refused UNIFORMLY. An app that is granted it is told
     * whether the person has connected and whether they must connect again, because it
     * cannot show the right button otherwise.
     *
     * @throws PipeLeaseDenied
     * @throws PipeConnectionMissing
     * @throws PipeReauthorizationRequired
     * @throws PipeRefreshFailed when a needed refresh could not complete right now
     */
    public function lease(string $provider, string $userId, string $clientId, string $purpose): PipeAccessToken;

    /**
     * Refresh one connection, single-flight: one process spends the refresh token, the
     * rest wait for it (`$wait`) or step aside (the background sweep). Without `$force`,
     * a connection that another process refreshed meanwhile is left alone.
     *
     * A provider that refuses the refresh token marks the connection `needs_reauth` and
     * emits `pipe.connection.needs_reauth`; the connection comes back in that state rather
     * than as an exception.
     *
     * @throws PipeConnectionNotFound
     * @throws PipeRefreshFailed on a transient failure (counted and audited first)
     */
    public function refresh(string $connectionId, bool $force = false, bool $wait = true): PipeConnection;

    /**
     * The background sweep's refresh: only when the access token expires within
     * `$withinSeconds`, and never waiting — a connection another process is refreshing is
     * skipped, not queued behind.
     *
     * @throws PipeConnectionNotFound
     * @throws PipeRefreshFailed on a transient failure (counted and audited first)
     */
    public function refreshIfExpiring(string $connectionId, int $withinSeconds): PipeConnection;
}
