<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\MfaRecoveryCode;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Concerns\FormatsRecoveryCodes;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;

class MfaService implements Mfa
{
    use FormatsRecoveryCodes;

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

        $step = $this->totp->matchStep($secret, $code);

        if ($step === null) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now(), 'last_used_step' => $step])->save();

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

        $step = $this->totp->matchStep($secret, $code);

        // Reject a code that matched no step, and one at or before the last step we
        // already accepted — that is a replay within the still-valid skew window.
        if ($step === null || ($factor->last_used_step !== null && $step <= $factor->last_used_step)) {
            return false;
        }

        $factor->forceFill(['last_used_step' => $step])->save();

        return true;
    }

    public function hasConfirmedTotp(string $userId): bool
    {
        $factor = $this->totpFactor($userId);

        return $factor !== null && $factor->confirmed_at !== null;
    }

    public function generateRecoveryCodes(string $userId, int $count = 10): array
    {
        // Replace any existing codes: regenerating invalidates the old set.
        MfaRecoveryCode::query()->where('user_id', $userId)->delete();

        $codes = [];

        for ($i = 0; $i < max(1, $count); $i++) {
            // 8 bytes = 64 bits of entropy, so a fast-hash offline attack on a
            // leaked hash is infeasible even though the code is single-use.
            $code = $this->formatRecoveryCode(bin2hex(random_bytes(8)));
            $codes[] = $code;

            MfaRecoveryCode::query()->create([
                'user_id' => $userId,
                'code_hash' => hash('sha256', $this->normalizeRecoveryCode($code)),
            ]);
        }

        $this->audit->record(new AuditEvent(
            action: 'user.mfa_recovery_generated',
            actorType: ActorType::User,
            actorId: $userId,
            targetType: 'user',
            targetId: $userId,
            context: ['count' => count($codes)],
        ));

        return $codes;
    }

    public function verifyRecoveryCode(string $userId, string $code): bool
    {
        $hash = hash('sha256', $this->normalizeRecoveryCode($code));

        $match = MfaRecoveryCode::query()
            ->where('user_id', $userId)
            ->whereNull('used_at')
            ->get()
            ->first(fn (MfaRecoveryCode $candidate): bool => hash_equals($candidate->code_hash, $hash));

        if ($match === null) {
            return false;
        }

        $match->forceFill(['used_at' => now()])->save();

        $this->audit->record(new AuditEvent(
            action: 'user.mfa_recovery_used',
            actorType: ActorType::User,
            actorId: $userId,
            targetType: 'user',
            targetId: $userId,
            context: ['remaining' => $this->remainingRecoveryCodes($userId)],
        ));

        return true;
    }

    public function remainingRecoveryCodes(string $userId): int
    {
        return MfaRecoveryCode::query()->where('user_id', $userId)->whereNull('used_at')->count();
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
