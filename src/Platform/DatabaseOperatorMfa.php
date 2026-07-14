<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\MfaService;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Concerns\FormatsRecoveryCodes;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;
use Cbox\Id\Platform\Contracts\OperatorMfa;
use Cbox\Id\Platform\Models\OperatorMfaFactor;
use Cbox\Id\Platform\Models\OperatorMfaRecoveryCode;

/**
 * Operator TOTP + recovery codes. Mirrors the subject {@see MfaService}
 * but persists against the operator tables (not environment-owned) and audits as
 * {@see ActorType::Operator}. It shares the vetted primitives — the RFC 6238
 * {@see TotpAuthenticator}, the {@see SecretBox} for sealing secrets at rest, and
 * the recovery-code formatting trait — so the two subsystems can't drift on the
 * security-relevant parts while staying independent identity planes.
 */
final class DatabaseOperatorMfa implements OperatorMfa
{
    use FormatsRecoveryCodes;

    public function __construct(
        private readonly TotpAuthenticator $totp,
        private readonly SecretBox $secretBox,
        private readonly AuditLog $audit,
    ) {}

    public function enrollTotp(string $operatorId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment
    {
        $secret = $this->totp->generateSecret();

        OperatorMfaFactor::query()->updateOrCreate(
            ['operator_id' => $operatorId, 'type' => 'totp'],
            ['secret_encrypted' => $this->secretBox->seal($secret, $this->context($operatorId)), 'confirmed_at' => null],
        );

        return new TotpEnrollment($secret, $this->totp->provisioningUri($secret, $account, $issuer));
    }

    public function confirmTotp(string $operatorId, string $code): bool
    {
        $factor = $this->totpFactor($operatorId);

        if ($factor === null) {
            return false;
        }

        $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($operatorId));

        $step = $this->totp->matchStep($secret, $code);

        if ($step === null) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now(), 'last_used_step' => $step])->save();

        $this->record('operator.mfa_enrolled', $operatorId, ['type' => 'totp']);

        return true;
    }

    public function verifyTotp(string $operatorId, string $code): bool
    {
        $factor = $this->totpFactor($operatorId);

        if ($factor === null || $factor->confirmed_at === null) {
            return false;
        }

        $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($operatorId));

        $step = $this->totp->matchStep($secret, $code);

        // Reject a code that matched no step, and one at or before the last step we
        // already accepted — that is a replay within the still-valid skew window.
        if ($step === null || ($factor->last_used_step !== null && $step <= $factor->last_used_step)) {
            return false;
        }

        $factor->forceFill(['last_used_step' => $step])->save();

        return true;
    }

    public function hasConfirmedTotp(string $operatorId): bool
    {
        $factor = $this->totpFactor($operatorId);

        return $factor !== null && $factor->confirmed_at !== null;
    }

    public function disable(string $operatorId): void
    {
        OperatorMfaFactor::query()->where('operator_id', $operatorId)->delete();
        OperatorMfaRecoveryCode::query()->where('operator_id', $operatorId)->delete();

        $this->record('operator.mfa_disabled', $operatorId);
    }

    public function generateRecoveryCodes(string $operatorId, int $count = 10): array
    {
        // Replace any existing codes: regenerating invalidates the old set.
        OperatorMfaRecoveryCode::query()->where('operator_id', $operatorId)->delete();

        $codes = [];

        for ($i = 0; $i < max(1, $count); $i++) {
            // 8 bytes = 64 bits of entropy, so a fast-hash offline attack on a
            // leaked hash is infeasible even though the code is single-use.
            $code = $this->formatRecoveryCode(bin2hex(random_bytes(8)));
            $codes[] = $code;

            OperatorMfaRecoveryCode::query()->create([
                'operator_id' => $operatorId,
                'code_hash' => hash('sha256', $this->normalizeRecoveryCode($code)),
            ]);
        }

        $this->record('operator.mfa_recovery_generated', $operatorId, ['count' => count($codes)]);

        return $codes;
    }

    public function verifyRecoveryCode(string $operatorId, string $code): bool
    {
        $hash = hash('sha256', $this->normalizeRecoveryCode($code));

        $match = OperatorMfaRecoveryCode::query()
            ->where('operator_id', $operatorId)
            ->whereNull('used_at')
            ->get()
            ->first(fn (OperatorMfaRecoveryCode $candidate): bool => hash_equals($candidate->code_hash, $hash));

        if ($match === null) {
            return false;
        }

        $match->forceFill(['used_at' => now()])->save();

        $this->record('operator.mfa_recovery_used', $operatorId, ['remaining' => $this->remainingRecoveryCodes($operatorId)]);

        return true;
    }

    public function remainingRecoveryCodes(string $operatorId): int
    {
        return OperatorMfaRecoveryCode::query()->where('operator_id', $operatorId)->whereNull('used_at')->count();
    }

    private function totpFactor(string $operatorId): ?OperatorMfaFactor
    {
        return OperatorMfaFactor::query()->where('operator_id', $operatorId)->where('type', 'totp')->first();
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function record(string $action, string $operatorId, array $context = []): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::Operator,
            actorId: $operatorId,
            targetType: 'operator',
            targetId: $operatorId,
            context: $context,
        ));
    }

    private function context(string $operatorId): string
    {
        return 'cbox-id:operator-mfa:'.$operatorId;
    }
}
