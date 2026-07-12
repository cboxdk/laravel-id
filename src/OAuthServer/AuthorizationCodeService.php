<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\AuthorizationCode;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Illuminate\Support\Facades\DB;

final class AuthorizationCodeService implements AuthorizationCodes
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
    ): string {
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
