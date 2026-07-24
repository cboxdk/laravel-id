<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The parameters an RP sends to the `end_session_endpoint` (OpenID Connect
 * RP-Initiated Logout 1.0 §2). Every field is optional per the spec — a bare
 * logout is valid — but a `postLogoutRedirectUri` is only ever honored when the
 * requesting client can be identified (explicit `clientId`, or the `aud` of a
 * verifiable `idTokenHint`) AND the URI is on that client's allow-list.
 */
readonly class EndSessionRequest
{
    public function __construct(
        public ?string $idTokenHint = null,
        public ?string $clientId = null,
        public ?string $postLogoutRedirectUri = null,
        public ?string $state = null,
    ) {}
}
