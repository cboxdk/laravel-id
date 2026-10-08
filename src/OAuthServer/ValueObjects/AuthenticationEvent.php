<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;

/**
 * When and how the person behind a grant authenticated — the facts RFC 9470 §6.1 puts on
 * an access token as `auth_time` and `acr`, so a resource server can decide whether the
 * login is recent and strong enough for what is being asked of it.
 *
 * Established at authentication time and never changed afterwards: a refreshed token
 * carries the ORIGINAL event (RFC 9470 §6.1, OIDC Core §12.2), which is why the rotation
 * family records `auth_time` and `amr` rather than the refresh re-reading anything.
 *
 * `acr` is DERIVED from `amr` through {@see AuthenticationContextClass::forAmr()} — the
 * same derivation the ID Token uses — and never taken from what was requested. A token
 * therefore cannot claim a class higher than the login achieved.
 */
readonly class AuthenticationEvent
{
    /**
     * @param  int|null  $authTime  unix time of the authentication, or null when unknown
     * @param  list<string>  $amr  the methods used (OIDC `amr`)
     */
    public function __construct(
        public ?int $authTime = null,
        public array $amr = [],
    ) {}

    public static function fromAuthorization(AuthorizedGrant $grant): self
    {
        return new self($grant->authTime, $grant->amr);
    }

    public static function fromRefresh(RefreshGrant $grant): self
    {
        return new self($grant->authTime, $grant->amr);
    }

    /**
     * The class this authentication achieved, or null when no method was recorded.
     *
     * Null rather than `aal1` for an empty `amr`, matching the ID Token, which omits
     * `acr` in that case: a grant that recorded nothing about HOW the person signed in
     * (a CIBA approval, a legacy code) should not assert even the lowest level.
     */
    public function acr(): ?AuthenticationContextClass
    {
        return $this->amr === [] ? null : AuthenticationContextClass::forAmr($this->amr);
    }

    public function isEmpty(): bool
    {
        return $this->authTime === null && $this->amr === [];
    }

    /**
     * The access-token claims: `auth_time` when known, `acr` when derivable.
     *
     * @return array{auth_time?: int, acr?: string}
     */
    public function claims(): array
    {
        $claims = [];

        if ($this->authTime !== null) {
            $claims['auth_time'] = $this->authTime;
        }

        $acr = $this->acr();

        if ($acr !== null) {
            $claims['acr'] = $acr->value;
        }

        return $claims;
    }
}
