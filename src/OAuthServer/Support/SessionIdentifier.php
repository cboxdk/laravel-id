<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\Kernel\Crypto\Support\Base64Url;

/**
 * The OIDC `sid` for a sign-in session (Back-Channel Logout 1.0 §2.1 / §2.4).
 *
 * DERIVED, NOT THE SESSION ID ITSELF. Every relying party the session signs a person in
 * to receives this value, so it must say nothing a relying party should not know: the
 * internal row key is a ULID, which dates the session to the millisecond and is the
 * handle the host's own session screens are addressed by. A SHA-256 over it names the
 * same session to every relying party (the spec's "one sid per OP session") and cannot be
 * turned back into the key.
 *
 * DETERMINISTIC, so nothing needs storing: the token endpoint computes it when it mints
 * an ID Token and the logout fan-out computes it again when the session ends, and the two
 * always agree. A keyed hash would buy nothing here — the input already carries 80 random
 * bits — and would break every outstanding `sid` the day the key rotated.
 */
class SessionIdentifier
{
    /** Domain separation, so this digest is never mistaken for any other hash of a session id. */
    private const CONTEXT = 'cbox-id/oidc-sid/v1:';

    public static function sid(string $sessionId): string
    {
        return Base64Url::encode(hash('sha256', self::CONTEXT.$sessionId, true));
    }
}
