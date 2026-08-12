<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\AuthorizationCode;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Illuminate\Support\Facades\DB;

class AuthorizationCodeService implements AuthorizationCodes
{
    private const TTL_SECONDS = 60;

    public function issue(
        string $clientId,
        string $userId,
        ?string $organizationId,
        string $redirectUri,
        array $scopes,
        string $codeChallenge,
        string $codeChallengeMethod = 'S256',
        ?string $nonce = null,
        ?int $authTime = null,
        array $amr = [],
        ?string $resource = null,
    ): string {
        // S256 ONLY, REFUSED AT ISSUE TIME. Redemption always computes S256, so a code
        // minted with `plain` could never be redeemed — it failed closed, which is the
        // right direction and the wrong moment: the host got a working code and a user
        // got a broken sign-in, with the error arriving at the exchange where nothing
        // says which of the two ends was wrong. RFC 7636 §4.2 permits `plain` only where
        // S256 is unavailable, which is not a case that exists on a PHP server.
        if ($codeChallengeMethod !== 'S256') {
            throw InvalidGrant::make('code_challenge_method must be S256');
        }

        // RFC 7636 §4.2: the challenge is base64url of a SHA-256 digest, so it is 43
        // characters of the unreserved set. Anything else is a host bug, and storing it
        // means the failure surfaces one round trip later against the verifier.
        if (preg_match('/^[A-Za-z0-9\-._~]{43}$/', $codeChallenge) !== 1) {
            throw InvalidGrant::make('code_challenge is not a base64url-encoded S256 digest');
        }

        $code = 'ac_'.bin2hex(random_bytes(32));

        AuthorizationCode::query()->create([
            'code_hash' => hash('sha256', $code),
            'client_id' => $clientId,
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'redirect_uri' => $redirectUri,
            'scopes' => $scopes,
            'pkce_challenge' => $codeChallenge,
            'pkce_method' => $codeChallengeMethod,
            'nonce' => $nonce,
            'auth_time' => $authTime,
            'amr' => $amr === [] ? null : $amr,
            // What the user authorized this code FOR (RFC 8707 §2). The token endpoint
            // compares any requested resource against this rather than trusting it.
            'resource' => $resource,
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
        ]);

        return $code;
    }

    public function exchange(string $clientId, string $code, string $redirectUri, string $codeVerifier): AuthorizedGrant
    {
        return DB::transaction(function () use ($clientId, $code, $redirectUri, $codeVerifier): AuthorizedGrant {
            $record = $this->locked($code);

            if ($record === null || $record->consumed_at !== null || $record->expires_at->isPast()) {
                throw InvalidGrant::make('code invalid, expired or already used');
            }

            if (! hash_equals($record->client_id, $clientId)) {
                throw InvalidGrant::make('client mismatch');
            }

            if (! hash_equals($record->redirect_uri, $redirectUri)) {
                throw InvalidGrant::make('redirect_uri mismatch');
            }

            // RFC 7636 §4.1: the verifier is 43–128 characters of `[A-Za-z0-9-._~]`.
            // Checked because the ABNF is the security property — it is what makes the
            // verifier hold the entropy the challenge commits to — and a short or
            // out-of-alphabet one is a client bug worth naming rather than a silent
            // hash mismatch.
            if (preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $codeVerifier) !== 1) {
                throw InvalidGrant::make('code_verifier must be 43-128 unreserved characters');
            }

            // PKCE S256: challenge = base64url(sha256(verifier)).
            $expected = Base64Url::encode(hash('sha256', $codeVerifier, true));

            if (! hash_equals($record->pkce_challenge, $expected)) {
                throw InvalidGrant::make('PKCE verification failed');
            }

            $record->forceFill(['consumed_at' => now()])->save();

            return new AuthorizedGrant(
                $record->user_id,
                $record->organization_id,
                array_values($record->scopes),
                $record->nonce,
                $record->auth_time,
                is_array($record->amr) ? array_values($record->amr) : [],
                $record->resource,
            );
        });
    }

    private function locked(string $code): ?AuthorizationCode
    {
        return AuthorizationCode::query()
            ->where('code_hash', hash('sha256', $code))
            ->lockForUpdate()
            ->first();
    }
}
