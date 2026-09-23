<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * What an authorization code for a support session is bound to on the app's side: the
 * redirect URI the app will redeem it with, and its PKCE challenge (S256). The same
 * inputs as any authorization request — the app completes an ordinary code exchange.
 */
readonly class SupportCodeRequest
{
    public function __construct(
        public string $redirectUri,
        public string $codeChallenge,
        public ?string $nonce = null,
    ) {}
}
