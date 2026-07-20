<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\EndSession;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\EndSessionRequest;
use Cbox\Id\OAuthServer\ValueObjects\EndSessionResult;

/**
 * RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0).
 *
 * The security-critical job here is NOT the session teardown (the controller does
 * that) — it is refusing to become an open redirector. A `post_logout_redirect_uri`
 * is honored ONLY when we can name the requesting client and the URI is byte-for-byte
 * on that client's registered allow-list. The client is identified from the explicit
 * `client_id`, or from the `aud` of an `id_token_hint` we actually verify against our
 * own signing keys (alg-pinned). An unverifiable hint is treated as absent rather than
 * trusted — a forged hint can never widen the redirect allow-list.
 */
class EndSessionService implements EndSession
{
    /** id_token_hint is signed with the same asymmetric algs as our id/access tokens. */
    private const HINT_ALGS = [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::EdDSA];

    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly TokenSigner $signer,
    ) {}

    public function resolve(EndSessionRequest $request): EndSessionResult
    {
        $hint = $this->verifyHint($request->idTokenHint);
        $subject = $hint['sub'] ?? null;

        $client = $this->resolveClient($request->clientId, $hint['aud'] ?? null);

        $redirectTo = $this->validatedRedirect($client, $request->postLogoutRedirectUri, $request->state);

        return new EndSessionResult($redirectTo, $subject);
    }

    /**
     * Verify the id_token_hint against our own keys and return its subject/audience.
     * An expired, forged, or malformed hint verifies to nothing — it is ignored, not
     * an error, so logout stays robust while never trusting an unverified token.
     *
     * @return array{sub: ?string, aud: ?string}
     */
    private function verifyHint(?string $hint): array
    {
        if (! is_string($hint) || $hint === '') {
            return ['sub' => null, 'aud' => null];
        }

        try {
            // The hint proves IDENTITY, not liveness — id_tokens are short-lived (15 min)
            // and logout routinely happens after expiry, so verify the signature but not
            // `exp` (OIDC RP-Initiated Logout §2/§4). Signature/alg pinning is unchanged,
            // so a forged hint is still rejected → treated as absent.
            $claims = $this->signer->verifyIgnoringExpiry($hint, self::HINT_ALGS);
        } catch (InvalidToken) {
            return ['sub' => null, 'aud' => null];
        }

        $aud = $claims->get('aud');

        return [
            'sub' => $claims->subject(),
            // `aud` may be a string or an array of audiences (OIDC Core §2); the
            // client id is the sole audience of an id_token in the common case.
            'aud' => is_string($aud) ? $aud : (is_array($aud) && isset($aud[0]) && is_string($aud[0]) ? $aud[0] : null),
        ];
    }

    private function resolveClient(?string $explicitClientId, ?string $hintAudience): ?Client
    {
        $clientId = ($explicitClientId !== null && $explicitClientId !== '') ? $explicitClientId : $hintAudience;

        // If both are present they MUST agree — a client_id that contradicts the
        // hint's audience is a malformed/hostile request; identify nobody.
        if ($explicitClientId !== null && $explicitClientId !== '' && $hintAudience !== null && $explicitClientId !== $hintAudience) {
            return null;
        }

        return ($clientId === null || $clientId === '') ? null : $this->clients->byClientId($clientId);
    }

    private function validatedRedirect(?Client $client, ?string $requested, ?string $state): ?string
    {
        if ($client === null || ! is_string($requested) || $requested === '') {
            return null;
        }

        $allowed = $client->post_logout_redirect_uris ?? [];

        // Exact string match, per RFC 6749 §3.1.2.3 redirect-URI matching applied to
        // the post-logout list — no substring/prefix leniency that a lookalike could slip through.
        if (! in_array($requested, $allowed, true)) {
            return null;
        }

        if ($state === null || $state === '') {
            return $requested;
        }

        $separator = str_contains($requested, '?') ? '&' : '?';

        return $requested.$separator.'state='.rawurlencode($state);
    }
}
