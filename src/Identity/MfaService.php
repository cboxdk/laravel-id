<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Mfa\TotpAuthenticator;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\ValueObjects\TotpEnrollment;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;

final class MfaService implements Mfa
{
    public function __construct(
        private readonly TotpAuthenticator $totp,
        private readonly SecretBox $secretBox,
        private readonly AuditLog $audit,
    ) {}

    public function enrollTotp(string $userId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment
    {
        $secret = $this->totp->generateSecret();

        MfaFactor::query()->updateOrCreate(
            ['user_id' => $userId, 'type' => 'totp'],
            ['secret_encrypted' => $this->secretBox->seal($secret, $this->context($userId)), 'confirmed_at' => null],
        );

        return new TotpEnrollment($secret, $this->totp->provisioningUri($secret, $account, $issuer));
    }

    public function confirmTotp(string $userId, string $code): bool
    {
        $factor = $this->totpFactor($userId);

        if ($factor === null) {
            return false;
        }

        $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($userId));

        if (! $this->totp->verify($secret, $code)) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now()])->save();

        $this->audit->record(new AuditEvent(
            action: 'user.mfa_enrolled',
            actorType: ActorType::User,
            actorId: $userId,
            targetType: 'user',
            targetId: $userId,
            context: ['type' => 'totp'],
        ));

        return true;
    }

    public function verifyTotp(string $userId, string $code): bool
    {
        $factor = $this->totpFactor($userId);

        if ($factor === null || $factor->confirmed_at === null) {
            return false;
        }

        $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($userId));

        return $this->totp->verify($secret, $code);
    }

    public function hasConfirmedTotp(string $userId): bool
    {
        $factor = $this->totpFactor($userId);

        return $factor !== null && $factor->confirmed_at !== null;
    }

    private function totpFactor(string $userId): ?MfaFactor
    {
        return MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')->first();
    }

    private function context(string $userId): string
    {
        return 'cbox-id:mfa:'.$userId;
    }
}
