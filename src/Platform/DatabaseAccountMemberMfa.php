<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Concerns\FormatsRecoveryCodes;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;
use Cbox\Id\Platform\Contracts\AccountMemberMfa;
use Cbox\Id\Platform\Models\AccountMfaFactor;
use Cbox\Id\Platform\Models\AccountMfaRecoveryCode;

/**
 * Account-member TOTP + recovery codes. Mirrors {@see DatabaseOperatorMfa} exactly,
 * persisting against the account MFA tables and auditing as
 * {@see ActorType::AccountMember}. Shares the vetted primitives — RFC 6238
 * {@see TotpAuthenticator}, {@see SecretBox} for sealing secrets, the recovery-code
 * formatting trait — so the planes can't drift on the security-relevant parts.
 */
class DatabaseAccountMemberMfa implements AccountMemberMfa
{
    use FormatsRecoveryCodes;

    public function __construct(
        private readonly TotpAuthenticator $totp,
        private readonly SecretBox $secretBox,
        private readonly AuditLog $audit,
    ) {}

    public function enrollTotp(string $memberId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment
    {
        $secret = $this->totp->generateSecret();

        AccountMfaFactor::query()->updateOrCreate(
            ['account_member_id' => $memberId, 'type' => 'totp'],
            ['secret_encrypted' => $this->secretBox->seal($secret, $this->context($memberId)), 'confirmed_at' => null],
        );

        return new TotpEnrollment($secret, $this->totp->provisioningUri($secret, $account, $issuer));
    }

    public function confirmTotp(string $memberId, string $code): bool
    {
        $factor = $this->totpFactor($memberId);

        if ($factor === null) {
            return false;
        }

        $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($memberId));
        $step = $this->totp->matchStep($secret, $code);

        if ($step === null) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now(), 'last_used_step' => $step])->save();
        $this->record('account.mfa_enrolled', $memberId, ['type' => 'totp']);

        return true;
    }

    public function verifyTotp(string $memberId, string $code): bool
    {
        $factor = $this->totpFactor($memberId);

        if ($factor === null || $factor->confirmed_at === null) {
            return false;
        }

        $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($memberId));
        $step = $this->totp->matchStep($secret, $code);

        // Reject no-match and any step at or before the last accepted one (a replay
        // inside the still-valid skew window).
        if ($step === null || ($factor->last_used_step !== null && $step <= $factor->last_used_step)) {
            return false;
        }

        $factor->forceFill(['last_used_step' => $step])->save();

        return true;
    }

    public function hasConfirmedTotp(string $memberId): bool
    {
        $factor = $this->totpFactor($memberId);

        return $factor !== null && $factor->confirmed_at !== null;
    }

    public function disable(string $memberId): void
    {
        AccountMfaFactor::query()->where('account_member_id', $memberId)->delete();
        AccountMfaRecoveryCode::query()->where('account_member_id', $memberId)->delete();

        $this->record('account.mfa_disabled', $memberId);
    }

    public function generateRecoveryCodes(string $memberId, int $count = 10): array
    {
        AccountMfaRecoveryCode::query()->where('account_member_id', $memberId)->delete();

        $codes = [];

        for ($i = 0; $i < max(1, $count); $i++) {
            // 8 bytes = 64 bits of entropy, so an offline attack on a leaked hash is
            // infeasible even though the code is single-use.
            $code = $this->formatRecoveryCode(bin2hex(random_bytes(8)));
            $codes[] = $code;

            AccountMfaRecoveryCode::query()->create([
                'account_member_id' => $memberId,
                'code_hash' => hash('sha256', $this->normalizeRecoveryCode($code)),
            ]);
        }

        $this->record('account.mfa_recovery_generated', $memberId, ['count' => count($codes)]);

        return $codes;
    }

    public function verifyRecoveryCode(string $memberId, string $code): bool
    {
        $hash = hash('sha256', $this->normalizeRecoveryCode($code));

        $match = AccountMfaRecoveryCode::query()
            ->where('account_member_id', $memberId)
            ->whereNull('used_at')
            ->get()
            ->first(fn (AccountMfaRecoveryCode $candidate): bool => hash_equals($candidate->code_hash, $hash));

        if ($match === null) {
            return false;
        }

        $match->forceFill(['used_at' => now()])->save();
        $this->record('account.mfa_recovery_used', $memberId, ['remaining' => $this->remainingRecoveryCodes($memberId)]);

        return true;
    }

    public function remainingRecoveryCodes(string $memberId): int
    {
        return AccountMfaRecoveryCode::query()->where('account_member_id', $memberId)->whereNull('used_at')->count();
    }

    private function totpFactor(string $memberId): ?AccountMfaFactor
    {
        return AccountMfaFactor::query()->where('account_member_id', $memberId)->where('type', 'totp')->first();
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function record(string $action, string $memberId, array $context = []): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::AccountMember,
            actorId: $memberId,
            targetType: 'account_member',
            targetId: $memberId,
            context: $context,
        ));
    }

    private function context(string $memberId): string
    {
        return 'cbox-id:account-mfa:'.$memberId;
    }
}
