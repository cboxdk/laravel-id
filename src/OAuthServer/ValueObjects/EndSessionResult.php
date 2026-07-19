<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The outcome of resolving an {@see EndSessionRequest}: the subject the logout is
 * FOR (from a verified `id_token_hint`, when present — so the caller can revoke the
 * right sessions), and the single safe place to redirect afterwards. `redirectTo`
 * is non-null only when a `post_logout_redirect_uri` passed the allow-list check;
 * otherwise there is nowhere to send the user and the endpoint renders its own
 * logged-out response. This is the type that keeps the endpoint from open-redirecting.
 */
final readonly class EndSessionResult
{
    public function __construct(
        public ?string $redirectTo = null,
        public ?string $subject = null,
    ) {}

    public function hasRedirect(): bool
    {
        return $this->redirectTo !== null;
    }
}
