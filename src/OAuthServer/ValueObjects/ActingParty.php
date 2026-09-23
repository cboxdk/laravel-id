<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The party ACTING for the subject of a grant (RFC 8693 §4.1 `act`): who is really
 * holding the token, and the support session that authorizes it.
 *
 * Carried on an authorization code and the grant it redeems into. A grant with an acting
 * party is minted differently — `act` on every token, no refresh token, a lifetime capped
 * at the session's — and the token endpoint re-reads the session before minting, so the
 * session id here is a pointer to the authority, never the authority itself.
 */
readonly class ActingParty
{
    public function __construct(
        /** The actor's subject id — the `act.sub` claim. */
        public string $subject,
        public string $supportSessionId,
    ) {}

    /**
     * The RFC 8693 `act` claim value.
     *
     * @return array{sub: string}
     */
    public function claim(): array
    {
        return ['sub' => $this->subject];
    }
}
