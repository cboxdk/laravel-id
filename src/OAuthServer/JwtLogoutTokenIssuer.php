<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\LogoutTokenIssuer;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;
use Illuminate\Support\Str;

/**
 * The Logout Token (OpenID Connect Back-Channel Logout 1.0 §2.4).
 *
 * Claim by claim, because a relying party validates exactly these:
 *
 * - `iss`, `aud`, `iat`, `exp` — as an ID Token. The issuer is the ENVIRONMENT's, and the
 *   signature is the environment's key, so the RP verifies it against the JWKS it already
 *   uses for ID Tokens.
 * - `jti` — unique per token, so the RP can refuse a replay. Minted per delivery ATTEMPT:
 *   a retry after a lost response must not be refused as a replay of the one that did
 *   arrive, and logging out twice is harmless.
 * - `events` — `{"http://schemas.openid.net/event/backchannel-logout": {}}`, the member
 *   that makes this a logout token and not some other JWT.
 * - `sub` and/or `sid` — whom, and which session. At least one; {@see LogoutNotice}
 *   refuses to exist without.
 * - NO `nonce`. §2.4 forbids it outright, so a logout token can never be replayed into a
 *   relying party's ID Token validation as though it were one.
 *
 * `typ: logout+jwt` (§2.4, "RECOMMENDED") lets a relying party refuse an ID Token or an
 * access token presented at its logout endpoint without reasoning about claims.
 *
 * `exp` is two minutes out: the token is delivered server to server within seconds or not
 * at all, and every retry mints a fresh one, so a longer life only widens a replay window.
 */
class JwtLogoutTokenIssuer implements LogoutTokenIssuer
{
    public const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public const TYPE = 'logout+jwt';

    public const TTL_SECONDS = 120;

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly IssuerResolver $issuers,
    ) {}

    public function issue(Client $client, LogoutNotice $notice): string
    {
        $now = time();

        $claims = [
            'iss' => $this->issuers->issuer(),
            'aud' => $client->client_id,
            'iat' => $now,
            'exp' => $now + self::TTL_SECONDS,
            'jti' => (string) Str::uuid(),
            // An empty JSON OBJECT, not an empty array: `{}` is what §2.4 specifies, and
            // PHP encodes `[]` as `[]`, which a strict relying party rejects.
            'events' => [self::EVENT => (object) []],
        ];

        if ($notice->subject !== null) {
            $claims['sub'] = $notice->subject;
        }

        if ($notice->sid !== null) {
            $claims['sid'] = $notice->sid;
        }

        // The same algorithm as the ID Token (§2.4: "signed … using the same algorithm as
        // for ID Tokens"), from the one place that names it.
        return $this->signer->sign($claims, TokenController::ID_TOKEN_ALG, self::TYPE);
    }
}
