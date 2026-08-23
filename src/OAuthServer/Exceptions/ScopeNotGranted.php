<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A grant was asked for scopes the client is not registered to hold.
 *
 * `invalid_scope` per RFC 6749 §4.1.2.1, which RFC 8628 (device) and OIDC CIBA inherit.
 *
 * Raised rather than silently filtered because these grants are machine-initiated: the
 * request arrives before any user code or approval prompt exists, so refusing it costs a
 * developer one clear error at integration time instead of a token that quietly does less
 * than they asked for. The authorization-code path deliberately does the opposite — a
 * person is waiting there, and refusing mid-flow strands them.
 */
class ScopeNotGranted extends RuntimeException
{
    /**
     * @param  list<string>  $scopes  the scopes that were refused
     */
    public static function forClient(string $clientId, array $scopes): self
    {
        // NAMES THE REMEDY, not only the fault. This is the first thing a developer
        // wiring up a CLI sees when the app's scope ceiling is too tight, and "is not
        // registered for" describes a state without saying who can change it or where.
        return new self(sprintf(
            'Client [%s] is not registered for the requested scope(s): %s. '
            .'Either request only the scopes it holds, or add them to the app under '
            .'Apps & API keys in the console.',
            $clientId,
            implode(' ', $scopes),
        ));
    }
}
