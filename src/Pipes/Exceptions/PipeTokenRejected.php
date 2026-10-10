<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * The provider's token endpoint answered with an OAuth error. `error` is the provider's
 * own code (`invalid_grant`, Slack's `invalid_refresh_token`, HubSpot's
 * `BAD_REFRESH_TOKEN`), kept because it decides whether the connection is dead
 * ({@see self::revokesTheGrant()}) or the failure is ours (`invalid_client`).
 *
 * Never carries the response body: a provider that echoes the submitted token back in an
 * error description would otherwise put it in a log.
 */
class PipeTokenRejected extends RuntimeException
{
    /**
     * The codes that mean the person's authorization is gone — refreshing will never work
     * again, and only a new consent will. Everything else (a bad client secret, a
     * malformed request, a rate limit) is ours or the provider's to fix, and marking every
     * connection `needs_reauth` for it would send every user through consent for nothing.
     */
    private const REVOKED_GRANT_CODES = [
        'invalid_grant',
        'bad_refresh_token',
        'invalid_refresh_token',
        'token_revoked',
        'token_expired',
        'refresh_token_expired',
        'BAD_REFRESH_TOKEN',
    ];

    public function __construct(public readonly string $error, public readonly int $status)
    {
        parent::__construct("The provider refused the token request ({$error}).");
    }

    public function revokesTheGrant(): bool
    {
        return in_array($this->error, self::REVOKED_GRANT_CODES, true);
    }
}
