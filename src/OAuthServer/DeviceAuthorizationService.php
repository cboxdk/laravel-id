<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Exceptions\DeviceAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\DeviceAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\DeviceExpired;
use Cbox\Id\OAuthServer\Exceptions\DeviceSlowDown;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\ValueObjects\DeviceAuthorizationResult;
use Cbox\Id\OAuthServer\ValueObjects\DeviceGrant;
use Illuminate\Support\Facades\DB;

final class DeviceAuthorizationService implements DeviceAuthorization
{
    private const TTL_SECONDS = 600;      // the user has 10 minutes to approve

    private const POLL_INTERVAL = 5;      // minimum seconds between token polls

    /** Unambiguous user-code alphabet (no 0/O/1/I) — RFC 8628 §6.1. */
    private const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    public function request(Client $client, array $scopes): DeviceAuthorizationResult
    {
        $deviceCode = 'dvc_'.bin2hex(random_bytes(32));
        $userCode = $this->generateUserCode();
        $verificationUri = $this->verificationUri();

        DeviceCode::query()->create([
            'device_code_hash' => hash('sha256', $deviceCode),
            'user_code' => $userCode,
            'client_id' => $client->client_id,
            'scopes' => $scopes,
            'status' => 'pending',
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

    public function approve(string $userCode, string $userId, ?string $organizationId): bool
    {
        return $this->transitionPending($userCode, [
            'status' => 'approved',
            'user_id' => $userId,
            'organization_id' => $organizationId,
        ]);
    }

    public function deny(string $userCode): bool
    {
        return $this->transitionPending($userCode, ['status' => 'denied']);
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
        if ($record->status === 'denied') {
            throw new DeviceAccessDenied;
        }

        // A code already exchanged for a token is spent — never mint again.
        if ($record->status === 'redeemed') {
            throw new InvalidGrant('device_code already used');
        }

        if ($record->status !== 'approved') {
            $record->forceFill(['last_polled_at' => now()])->save();

            throw new DeviceAuthorizationPending;
        }

        // Single-use (RFC 8628 §3.4): a device_code mints a token exactly once.
        // Flip approved -> redeemed under a row lock inside a transaction so two
        // concurrent polls (a shared/logged code) can't both observe 'approved'
        // and each mint a token. The polling/pending saves above stay outside the
        // transaction so they commit even when this path throws.
        return DB::transaction(function () use ($record): DeviceGrant {
            $locked = DeviceCode::query()->whereKey($record->id)->lockForUpdate()->first();

            if ($locked === null || $locked->status !== 'approved') {
                throw new InvalidGrant('device_code already used');
            }

            $grant = new DeviceGrant(
                (string) $locked->user_id,
                $locked->organization_id,
                array_values($locked->scopes),
            );

            $locked->forceFill(['status' => 'redeemed', 'last_polled_at' => now()])->save();

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
            ->where('status', 'pending')
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
        $issuer = config('cbox-id.issuer');
        $base = is_string($issuer) && $issuer !== '' ? rtrim($issuer, '/') : rtrim((string) url('/'), '/');

        return $base.'/device';
    }
}
