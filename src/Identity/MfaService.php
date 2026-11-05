<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\TotpDevices;
use Cbox\Id\Identity\Exceptions\TotpDeviceRefused;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\MfaRecoveryCode;
use Cbox\Id\Identity\ValueObjects\TotpDevice;
use Cbox\Id\Identity\ValueObjects\TotpDeviceEnrollment;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Concerns\FormatsRecoveryCodes;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

class MfaService implements Mfa, TotpDevices
{
    use FormatsRecoveryCodes;

    public function __construct(
        private readonly TotpAuthenticator $totp,
        private readonly SecretBox $secretBox,
        private readonly AuditLog $audit,
    ) {}

    public function enrollTotp(string $userId, string $account, string $issuer = 'Cbox ID'): TotpEnrollment
    {
        return DB::transaction(function () use ($userId, $account, $issuer): TotpEnrollment {
            $factors = MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')
                ->orderBy('id')->lockForUpdate()->get();
            if ($factors->whereNotNull('confirmed_at')->isNotEmpty()) {
                throw new TotpDeviceRefused('already_enrolled');
            }
            $factor = $factors->firstWhere('slot', 0);
            if ($factor !== null && $factor->name !== '') {
                throw new TotpDeviceRefused('enrolment_busy');
            }
            $secret = $this->totp->generateSecret();
            $factor ??= new MfaFactor(['user_id' => $userId, 'type' => 'totp', 'slot' => 0]);
            $factor->forceFill([
                'secret_encrypted' => $this->secretBox->seal($secret, $this->context($userId)),
                'confirmed_at' => null, 'last_used_step' => null, 'created_at' => now(),
            ])->save();

            return new TotpEnrollment($secret, $this->totp->provisioningUri($secret, $account, $issuer));
        }, 3);
    }

    public function confirmTotp(string $userId, string $code): bool
    {
        $factor = $this->totpFactor($userId);

        return $factor !== null && $this->confirmDevice($userId, $factor->id, $code);
    }

    public function verifyTotp(string $userId, string $code): bool
    {
        return DB::transaction(function () use ($userId, $code): bool {
            $factors = MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')
                ->whereNotNull('confirmed_at')->orderBy('id')->lockForUpdate()->get();
            $matches = [];
            foreach ($factors as $factor) {
                $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($userId));
                $step = $this->totp->matchStep($secret, $code);
                if ($step === null) {
                    continue;
                }
                if ($factor->last_used_step !== null && $step <= $factor->last_used_step) {
                    return false;
                }
                $matches[$factor->id] = $step;
            }
            // Consume every matching step: two apps can exceptionally show the same
            // six digits. That collision must never make one code reusable.
            foreach ($matches as $id => $step) {
                $advanced = MfaFactor::query()->whereKey($id)->whereNotNull('confirmed_at')
                    ->where(fn ($query) => $query->whereNull('last_used_step')->orWhere('last_used_step', '<', $step))
                    ->update(['last_used_step' => $step]);
                if ($advanced !== 1) {
                    return false;
                }
            }

            return $matches !== [];
        }, 3);
    }

    public function hasConfirmedTotp(string $userId): bool
    {
        return MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')->whereNotNull('confirmed_at')->exists();
    }

    public function devices(string $userId): array
    {
        return array_values(MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')
            ->whereNotNull('confirmed_at')->orderBy('created_at')->orderBy('id')->get()
            ->map(fn (MfaFactor $factor): TotpDevice => new TotpDevice(
                $factor->id, $factor->name, $factor->confirmed_at?->toDateTimeImmutable(),
            ))->all());
    }

    public function enrollDevice(string $userId, string $account, string $name, string $issuer = 'Cbox ID'): TotpDeviceEnrollment
    {
        $name = $this->deviceName($name);
        for ($attempt = 0; $attempt < 3; $attempt++) {
            try {
                return DB::transaction(function () use ($userId, $account, $name, $issuer): TotpDeviceEnrollment {
                    // Ordered locks serialize changes to an existing set. The unique slot
                    // constraint also bounds concurrent first enrolments to ten secrets.
                    $factors = MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')->orderBy('id')->lockForUpdate()->get();
                    $used = [];
                    foreach ($factors as $factor) {
                        if ($factor->confirmed_at === null && $factor->created_at?->lt(now()->subMinutes(10))) {
                            $factor->delete();
                        } else {
                            $used[] = $factor->slot;
                        }
                    }
                    $slots = array_values(array_diff(range(0, 9), $used));
                    if ($slots === []) {
                        throw new TotpDeviceRefused('limit_reached');
                    }
                    $secret = $this->totp->generateSecret();
                    $factor = MfaFactor::query()->create([
                        'user_id' => $userId, 'type' => 'totp', 'slot' => $slots[0], 'name' => $name,
                        'secret_encrypted' => $this->secretBox->seal($secret, $this->context($userId)),
                    ]);

                    return new TotpDeviceEnrollment($factor->id, $secret, $this->totp->provisioningUri($secret, $account, $issuer));
                }, 3);
            } catch (UniqueConstraintViolationException) {
                // Another first enrolment claimed this slot. Retry after its transaction.
            }
        }

        throw new TotpDeviceRefused('enrolment_busy');
    }

    public function confirmDevice(string $userId, string $deviceId, string $code): bool
    {
        return DB::transaction(function () use ($userId, $deviceId, $code): bool {
            $factor = MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')
                ->whereKey($deviceId)->lockForUpdate()->first();
            if ($factor === null || $factor->confirmed_at !== null || $factor->created_at?->lt(now()->subMinutes(10))) {
                return false;
            }
            $secret = $this->secretBox->open($factor->secret_encrypted, $this->context($userId));
            $step = $this->totp->matchStep($secret, $code);
            if ($step === null) {
                return false;
            }
            $factor->forceFill(['confirmed_at' => now(), 'last_used_step' => $step])->save();
            $this->audit->record(new AuditEvent(
                action: 'user.mfa_enrolled', actorType: ActorType::User, actorId: $userId,
                targetType: 'user', targetId: $userId, context: ['type' => 'totp', 'factor_id' => $factor->id],
            ));

            return true;
        });
    }

    public function renameDevice(string $userId, string $deviceId, string $name): bool
    {
        $name = $this->deviceName($name);
        $factor = MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')
            ->whereNotNull('confirmed_at')->whereKey($deviceId)->first();
        if ($factor === null) {
            return false;
        }
        $factor->forceFill(['name' => $name])->save();
        $this->audit->record(new AuditEvent(
            action: 'user.mfa_renamed', actorType: ActorType::User, actorId: $userId,
            targetType: 'user', targetId: $userId, context: ['type' => 'totp', 'factor_id' => $deviceId],
        ));

        return true;
    }

    public function removeDevice(string $userId, string $deviceId): bool
    {
        return DB::transaction(function () use ($userId, $deviceId): bool {
            $factors = MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')
                ->orderBy('id')->lockForUpdate()->get();
            $factor = $factors->firstWhere('id', $deviceId);
            if ($factor === null) {
                return false;
            }
            if ($factor->confirmed_at !== null && $factors->whereNotNull('confirmed_at')->count() <= 1) {
                throw new TotpDeviceRefused('last_device');
            }
            $factor->delete();
            $this->audit->record(new AuditEvent(
                action: 'user.mfa_removed', actorType: ActorType::User, actorId: $userId,
                targetType: 'user', targetId: $userId, context: ['type' => 'totp', 'factor_id' => $deviceId],
            ));

            return true;
        }, 3);
    }

    private function deviceName(string $name): string
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 120 || preg_match('/[\\p{C}]/u', $name) !== 0) {
            throw new TotpDeviceRefused('invalid_name');
        }

        return $name;
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

        // Claim the code conditionally: two requests presenting the same recovery code at
        // once would both have found it unused above and both been let in, spending one
        // code on two sessions. Only the update that still sees it unused wins.
        $claimed = MfaRecoveryCode::query()
            ->whereKey($match->id)
            ->whereNull('used_at')
            ->update(['used_at' => now()]);

        if ($claimed !== 1) {
            return false;
        }

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

    /**
     * Remove every factor and recovery code for a user.
     *
     * Audited as `user.mfa_disabled`, deliberately with the SAME shape as the account
     * and operator planes' `*.mfa_disabled`, so an access review, a SIEM stream and a
     * customer's compliance export can read all three the same way. Without this verb
     * the console deleted the rows directly, and the trail showed nothing at all.
     */
    public function disable(string $userId, ?ActorType $actorType = null, ?string $actorId = null): void
    {
        MfaFactor::query()->where('user_id', $userId)->delete();
        MfaRecoveryCode::query()->where('user_id', $userId)->delete();

        // Default to self-service; an administrator passes their own identity. Hardcoding
        // the subject as the actor — which is what this method did when it was written —
        // records an admin stripping someone's second factor as that person having done
        // it themselves, erasing exactly the distinction the verb exists for.
        $this->audit->record(new AuditEvent(
            action: 'user.mfa_disabled',
            actorType: $actorType ?? ActorType::User,
            actorId: $actorId ?? $userId,
            targetType: 'user',
            targetId: $userId,
        ));
    }

    public function remainingRecoveryCodes(string $userId): int
    {
        return MfaRecoveryCode::query()->where('user_id', $userId)->whereNull('used_at')->count();
    }

    private function totpFactor(string $userId): ?MfaFactor
    {
        return MfaFactor::query()->where('user_id', $userId)->where('type', 'totp')->where('slot', 0)->first();
    }

    private function context(string $userId): string
    {
        return 'cbox-id:mfa:'.$userId;
    }
}
