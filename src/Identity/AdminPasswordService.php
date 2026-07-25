<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AdminPasswords;
use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\PasswordRevocationScope;
use Cbox\Id\Identity\Models\PasswordChangeRequirement;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\AdminPasswordAssignment;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Facades\DB;

/**
 * Administrative credential management. See {@see AdminPasswords} for why this is a
 * first-party capability and what it deliberately does NOT decide (authorization).
 */
class AdminPasswordService implements AdminPasswords
{
    public function __construct(
        private readonly Subjects $subjects,
        private readonly SessionManager $sessions,
        private readonly SubjectGrantRevoker $grants,
        private readonly PasswordPolicyGuard $policy,
        private readonly AuditLog $audit,
    ) {}

    public function assign(AdminPasswordAssignment $assignment): void
    {
        // The tenant's policy binds an ADMINISTRATOR too. A credential an admin hands
        // out is one the person may keep using, so exempting this path would leave the
        // weakest password on the platform sitting behind the highest privilege.
        $this->policy->assertAcceptable(
            $assignment->password,
            $assignment->userId,
            $assignment->organizationId,
        );

        DB::transaction(function () use ($assignment): void {
            $this->subjects->setPassword($assignment->userId, $assignment->password);
            $this->rememberForReuse($assignment);

            // A temporary credential carries a standing requirement to replace it; a
            // permanent one clears any requirement left over from an earlier hand-off.
            if ($assignment->temporary) {
                PasswordChangeRequirement::query()->updateOrCreate(
                    ['user_id' => $assignment->userId],
                    [
                        'expires_at' => $assignment->expiresAt,
                        'set_by_type' => $assignment->actorType,
                        'set_by_id' => $assignment->actorId,
                    ],
                );
            } else {
                $this->clear($assignment->userId);
            }

            // Blast radius is the administrator's explicit choice: recovering a
            // locked-out colleague is not the same situation as cutting off a
            // suspected compromise.
            if ($assignment->revoke !== PasswordRevocationScope::Nothing) {
                $this->sessions->revokeAllForUser($assignment->userId);
            }

            if ($assignment->revoke === PasswordRevocationScope::SessionsAndTokens) {
                $this->grants->revokeGrantsForUser($assignment->userId);
            }

            $this->audit->record(new AuditEvent(
                action: 'user.password_set_by_admin',
                actorType: $assignment->actorType !== null ? ActorType::Operator : ActorType::System,
                actorId: $assignment->actorId,
                targetType: 'user',
                targetId: $assignment->userId,
                context: [
                    'temporary' => $assignment->temporary,
                    'expires_at' => $assignment->expiresAt?->toIso8601String(),
                    'revoked' => $assignment->revoke->value,
                    'reason' => $assignment->reason,
                ],
            ));
        });
    }

    /**
     * Retain the newly-stored hash so a reuse policy can compare against it later. Read
     * back from the subject rather than re-hashing, so history holds exactly what
     * authentication will check.
     */
    private function rememberForReuse(AdminPasswordAssignment $assignment): void
    {
        $hash = User::query()->whereKey($assignment->userId)->value('password');

        if (is_string($hash) && $hash !== '') {
            $this->policy->remember($assignment->userId, $hash, $assignment->organizationId);
        }
    }

    public function requiresChange(string $userId): bool
    {
        return PasswordChangeRequirement::query()->where('user_id', $userId)->exists();
    }

    public function hasExpired(string $userId): bool
    {
        return PasswordChangeRequirement::query()
            ->where('user_id', $userId)
            ->first()?->hasExpired() ?? false;
    }

    public function clear(string $userId): void
    {
        PasswordChangeRequirement::query()->where('user_id', $userId)->delete();
    }
}
