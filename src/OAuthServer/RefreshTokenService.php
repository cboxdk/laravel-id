<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Exceptions\RefreshTokenReuse;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\ValueObjects\RefreshGrant;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Rotating refresh tokens with reuse detection (OAuth 2.0 Security BCP §4.13.2).
 * Each token is single-use: rotation consumes it and issues a successor sharing a
 * family id. Re-presenting a consumed token means the token leaked and both the
 * legitimate client and the attacker are racing on it — the safe response is to
 * revoke the entire family, forcing re-authentication.
 */
final class RefreshTokenService implements RefreshTokens
{
    private const TTL_DAYS = 30;

    public function issue(Client $client, ?string $userId, ?string $organizationId, array $scopes, ?string $audience = null, ?string $dpopJkt = null): string
    {
        return $this->mint((string) Str::ulid(), $client->client_id, $userId, $organizationId, $scopes, $audience, $dpopJkt);
    }

    public function rotate(string $clientId, string $rawToken, ?string $presentedJkt = null): RefreshGrant
    {
        try {
            return DB::transaction(function () use ($clientId, $rawToken, $presentedJkt): RefreshGrant {
                $token = RefreshToken::query()
                    ->where('token_hash', hash('sha256', $rawToken))
                    ->lockForUpdate()
                    ->first();

                if ($token === null || $token->revoked_at !== null || $token->expires_at->isPast()) {
                    throw InvalidGrant::make('refresh token invalid, expired or revoked');
                }

                // Reuse of an already-rotated token means it leaked. Signal the
                // family up so it can be revoked *after* this transaction — doing
                // it here would be rolled back by the exception below.
                if ($token->consumed_at !== null) {
                    throw new RefreshTokenReuse($token->family_id);
                }

                if (! hash_equals($token->client_id, $clientId)) {
                    throw InvalidGrant::make('client mismatch');
                }

                // RFC 9449 §5: a DPoP-bound refresh token may only be rotated by a
                // holder proving the same key. A stolen bound token presented with
                // the attacker's own (or no) key is refused.
                if ($token->jkt !== null && ($presentedJkt === null || ! hash_equals($token->jkt, $presentedJkt))) {
                    throw InvalidGrant::make('DPoP key does not match the refresh token binding');
                }

                $token->forceFill(['consumed_at' => now()])->save();

                $raw = $this->mint(
                    $token->family_id,
                    $token->client_id,
                    $token->user_id,
                    $token->organization_id,
                    array_values($token->scopes),
                    $token->audience,
                    $token->jkt,
                );

                return new RefreshGrant(
                    refreshToken: $raw,
                    clientId: $token->client_id,
                    userId: $token->user_id,
                    organizationId: $token->organization_id,
                    scopes: array_values($token->scopes),
                    audience: $token->audience,
                );
            });
        } catch (RefreshTokenReuse $reuse) {
            // Now that the read transaction has unwound, revoke the whole family.
            $this->revokeFamily($reuse->familyId);

            throw InvalidGrant::make('refresh token reuse detected');
        }
    }

    public function revoke(string $rawToken, ?string $clientId = null): void
    {
        $token = RefreshToken::query()->where('token_hash', hash('sha256', $rawToken))->first();

        if ($token === null) {
            return;
        }

        // Ownership (RFC 7009 §2.1): only the issuing client may revoke the family.
        if ($clientId !== null && ! hash_equals($token->client_id, $clientId)) {
            return;
        }

        $this->revokeFamily($token->family_id);
    }

    public function revokeForUser(string $userId, ?string $organizationId = null): int
    {
        return RefreshToken::query()
            ->where('user_id', $userId)
            ->when($organizationId !== null, fn ($query) => $query->where('organization_id', $organizationId))
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }

    /**
     * @param  list<string>  $scopes
     */
    private function mint(string $familyId, string $clientId, ?string $userId, ?string $organizationId, array $scopes, ?string $audience, ?string $dpopJkt = null): string
    {
        $raw = 'rt_'.bin2hex(random_bytes(32));

        RefreshToken::query()->create([
            'token_hash' => hash('sha256', $raw),
            'family_id' => $familyId,
            'client_id' => $clientId,
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'scopes' => $scopes,
            'audience' => $audience,
            'jkt' => $dpopJkt,
            'expires_at' => now()->addDays(self::TTL_DAYS),
        ]);

        return $raw;
    }

    private function revokeFamily(string $familyId): void
    {
        RefreshToken::query()
            ->where('family_id', $familyId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
