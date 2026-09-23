<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * What an access token is FOR: the scopes it may carry, the audience it is bound to, and
 * whose roles/permissions it stamps. Produced once per token by the audience resolver and
 * read by the issuer, so every grant type answers the same question the same way.
 */
readonly class ResolvedAudience
{
    /**
     * @param  list<string>  $scopes  the scopes the token carries — never more than it was asked for
     */
    public function __construct(
        public array $scopes,

        /**
         * The audience to bind, or null for the issuer itself (RFC 9068 §2.2 fallback).
         * A registered API's identifier, or an unregistered RFC 8707 resource verbatim.
         */
        public ?string $resource,

        /** The client whose declared roles/permissions the token carries. */
        public string $rbacClientId,

        /** The registered API the token is audienced to, if any. */
        public ?ApiAudience $api = null,

        /**
         * Whether the issuer is a second audience — true for a registered API token that
         * also carries `openid`, so the same token still opens UserInfo.
         */
        public bool $includesIssuer = false,
    ) {}

    /**
     * The `aud` claim value.
     *
     * @return string|list<string>
     */
    public function claim(string $issuer): string|array
    {
        if ($this->resource === null) {
            return $issuer;
        }

        return $this->includesIssuer && $this->resource !== $issuer
            ? [$this->resource, $issuer]
            : $this->resource;
    }
}
