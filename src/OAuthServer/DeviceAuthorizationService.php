<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Enums\GrantPollStatus;
use Cbox\Id\OAuthServer\Exceptions\DeviceAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\DeviceAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\DeviceExpired;
use Cbox\Id\OAuthServer\Exceptions\DeviceSlowDown;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGranted;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\Support\GrantedScopes;
use Cbox\Id\OAuthServer\ValueObjects\DeviceAuthorizationResult;
use Cbox\Id\OAuthServer\ValueObjects\DeviceGrant;
use Cbox\Id\OAuthServer\ValueObjects\PendingDeviceAuthorization;
use Illuminate\Support\Facades\DB;

class DeviceAuthorizationService implements DeviceAuthorization
{
    private const TTL_SECONDS = 600;      // the user has 10 minutes to approve

    private const POLL_INTERVAL = 5;      // minimum seconds between token polls

    /** Unambiguous user-code alphabet (no 0/O/1/I) — RFC 8628 §6.1. */
    private const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    public function request(Client $client, array $scopes): DeviceAuthorizationResult
    {
        // THE CEILING, APPLIED ONCE AND HERE. Storing what was asked for meant the token
        // endpoint later read unfiltered scopes to decide on a refresh token — see
        // GrantedScopes — so a client registered for `openid` alone asked for
        // `openid offline_access` and got a correctly downscoped access token AND a
        // refresh token carrying a scope its registration withheld.
        //
        // REFUSED, not silently narrowed. The authorization-code path filters quietly
        // because a person is standing in front of it and refusing mid-flow strands them.
        // Nobody is standing in front of THIS: it is a machine asking, before any user
        // code is shown, so the honest answer is `invalid_scope` (RFC 6749 §4.1.2.1, which
        // RFC 8628 §3.2 inherits). It also removes the question of what the token response
        // should echo — granted and requested cannot disagree if a disagreement is a 400.
        $granted = GrantedScopes::for($client, $scopes);

        if ($granted !== $scopes && $scopes !== []) {
            throw ScopeNotGranted::forClient($client->client_id, array_values(array_diff($scopes, $granted)));
        }

        $scopes = $granted;

        $deviceCode = 'dvc_'.bin2hex(random_bytes(32));
        $userCode = $this->generateUserCode();
        $verificationUri = $this->verificationUri();

        DeviceCode::query()->create([
            'device_code_hash' => hash('sha256', $deviceCode),
            'user_code' => $userCode,
            'client_id' => $client->client_id,
            'scopes' => $scopes,
            'status' => GrantPollStatus::Pending,
            'interval' => self::POLL_INTERVAL,
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
        ]);

        return new DeviceAuthorizationResult(
            deviceCode: $deviceCode,
            userCode: $userCode,
            verificationUri: $verificationUri,
            verificationUriComplete: $verificationUri.'?user_code='.$userCode,
            expiresIn: self::TTL_SECONDS,
            interval: self::POLL_INTERVAL,
            scopes: $scopes,
        );
    }

    public function pending(string $userCode): ?PendingDeviceAuthorization
    {
        $record = DeviceCode::query()
            ->where('user_code', strtoupper($userCode))
            ->where('status', GrantPollStatus::Pending)
            ->where('expires_at', '>', now())
            ->first();

        if ($record === null) {
            return null;
        }

        return new PendingDeviceAuthorization(
            clientId: $record->client_id,
            scopes: array_values($record->scopes),
            expiresAt: $record->expires_at->toDateTimeImmutable(),
        );
    }

    public function approve(string $userCode, string $userId, ?string $organizationId): bool
    {
        return $this->transitionPending($userCode, [
            'status' => GrantPollStatus::Approved,
            'user_id' => $userId,
            'organization_id' => $organizationId,
        ]);
    }

    public function deny(string $userCode): bool
    {
        return $this->transitionPending($userCode, ['status' => GrantPollStatus::Denied]);
    }

    public function redeem(string $clientId, string $deviceCode): DeviceGrant
    {
        $record = DeviceCode::query()
            ->where('device_code_hash', hash('sha256', $deviceCode))
            ->where('client_id', $clientId)
            ->first();

        if ($record === null) {
            throw new InvalidGrant('unknown device_code');
        }

        if ($record->expires_at->isPast()) {
            throw new DeviceExpired;
        }

        // Enforce the polling interval (RFC 8628 §3.5): too-fast polling gets
        // slow_down without advancing the clock. NB: the timestamp update below
        // must be committed *before* the pending/denied throw — otherwise a
        // rolled-back transaction would let the client poll unthrottled.
        if ($record->last_polled_at !== null
            && $record->last_polled_at->copy()->addSeconds($record->interval)->isFuture()) {
            throw new DeviceSlowDown;
        }
        if ($record->status === GrantPollStatus::Denied) {
            throw new DeviceAccessDenied;
        }

        // A code already exchanged for a token is spent — never mint again.
        if ($record->status === GrantPollStatus::Redeemed) {
            throw new InvalidGrant('device_code already used');
        }

        if ($record->status !== GrantPollStatus::Approved) {
            $record->forceFill(['last_polled_at' => now()])->save();

            throw new DeviceAuthorizationPending;
        }

        // Single-use (RFC 8628 §3.4): a device_code mints a token exactly once.
        // Flip approved -> redeemed under a row lock inside a transaction so two
        // concurrent polls (a shared/logged code) can't both observe Approved
        // and each mint a token. The polling/pending saves above stay outside the
        // transaction so they commit even when this path throws.
        return DB::transaction(function () use ($record): DeviceGrant {
            $locked = DeviceCode::query()->whereKey($record->id)->lockForUpdate()->first();

            if ($locked === null || $locked->status !== GrantPollStatus::Approved) {
                throw new InvalidGrant('device_code already used');
            }

            $grant = new DeviceGrant(
                (string) $locked->user_id,
                $locked->organization_id,
                array_values($locked->scopes),
            );

            $locked->forceFill(['status' => GrantPollStatus::Redeemed, 'last_polled_at' => now()])->save();

            return $grant;
        });
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function transitionPending(string $userCode, array $attributes): bool
    {
        return (bool) DeviceCode::query()
            ->where('user_code', strtoupper($userCode))
            ->where('status', GrantPollStatus::Pending)
            ->where('expires_at', '>', now())
            ->update($attributes);
    }

    private function generateUserCode(): string
    {
        $pick = static function (): string {
            $out = '';
            for ($i = 0; $i < 4; $i++) {
                $out .= self::USER_CODE_ALPHABET[random_int(0, strlen(self::USER_CODE_ALPHABET) - 1)];
            }

            return $out;
        };

        return $pick().'-'.$pick();
    }

    private function verificationUri(): string
    {
        // Per-environment issuer host, so the device verification URL is on the same
        // tenant host the user is already talking to.
        return app(IssuerResolver::class)->issuer().'/device';
    }
}
