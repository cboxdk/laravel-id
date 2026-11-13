<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\MailboxProof;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\EmailVerificationToken;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\LoginAttemptCounter;
use Cbox\Id\Identity\Models\MagicLinkToken;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\MfaRecoveryCode;
use Cbox\Id\Identity\Models\PasswordAge;
use Cbox\Id\Identity\Models\PasswordChangeRequirement;
use Cbox\Id\Identity\Models\PasswordHistoryEntry;
use Cbox\Id\Identity\Models\PasswordResetToken;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesTenant;
use Cbox\Id\Organization\Models\CustomerApiKey;
use Cbox\Id\Organization\Models\UserApiToken;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see MailboxProof}, over the package's own credential stores.
 *
 * What is withdrawn, and how:
 *
 *  - the password (nulled on the default users table — see {@see removePassword()}), its
 *    history, age and any pending forced change, and the lockout counter;
 *  - every second factor (TOTP, SMS) and recovery code, and every passkey;
 *  - every link to an external identity provider;
 *  - outstanding verification tokens for the account, and password-reset and sign-in
 *    links for the address (those two stores are keyed by address, not by account);
 *  - personal API tokens and the customer API keys the account created, in every
 *    organization — REVOKED, not deleted, so their audit history keeps its subject;
 *  - every OAuth grant, refresh and access tokens both ({@see SubjectGrantRevoker});
 *  - every session, through the {@see SessionManager} so relying parties hear of it.
 *
 * The person who proved the mailbox signs in afterwards and sets their own credentials.
 */
class DatabaseMailboxProof implements MailboxProof
{
    use ResolvesTenant;

    public function __construct(
        private readonly Subjects $subjects,
        private readonly SessionManager $sessions,
        private readonly SubjectGrantRevoker $grants,
        private readonly AuditLog $audit,
    ) {}

    public function claim(Subject $subject, string $provenEmail): Subject
    {
        return DB::transaction(function () use ($subject, $provenEmail): Subject {
            $this->lock($subject->id);

            // Decide on the account as it stands now, not on the copy the caller held: it
            // may have been verified, or had its address changed, since that was read.
            $current = $this->subjects->find($subject->id);

            if ($current === null || $current->emailVerified || $current->email === null
                || mb_strtolower($current->email) !== mb_strtolower($provenEmail)) {
                return $current ?? $subject;
            }

            $id = $current->id;
            $address = mb_strtolower($current->email);

            $removed = [
                'password' => $this->removePassword($id),
                'mfa_factors' => $this->delete(MfaFactor::query()->where('user_id', $id)),
                'recovery_codes' => $this->delete(MfaRecoveryCode::query()->where('user_id', $id)),
                'passkeys' => $this->delete(WebAuthnCredential::query()->where('user_id', $id)),
                'federated_identities' => $this->delete(IdentityLink::query()->where('user_id', $id)),
                'password_reset_tokens' => $this->delete(PasswordResetToken::query()->whereRaw('lower(email) = ?', [$address])),
                'magic_links' => $this->delete(MagicLinkToken::query()->whereRaw('lower(email) = ?', [$address])),
                'api_tokens' => $this->revokeApiTokens($id),
                'sessions' => Session::query()->where('user_id', $id)->whereNull('revoked_at')->count(),
            ];

            foreach ([
                PasswordHistoryEntry::query()->where('user_id', $id),
                PasswordAge::query()->where('user_id', $id),
                PasswordChangeRequirement::query()->where('user_id', $id),
                EmailVerificationToken::query()->where('user_id', $id),
                LoginAttemptCounter::query()->where('user_id', $id),
            ] as $query) {
                $this->delete($query);
            }

            $this->grants->revokeGrantsForUser($id);
            $this->sessions->revokeAllForUser($id);

            $this->subjects->markEmailVerified($id, $current->email);

            $this->audit->record(new AuditEvent(
                action: 'user.unverified_account_claimed',
                actorType: ActorType::System,
                targetType: 'user',
                targetId: $id,
                context: $removed,
            ));

            return $this->subjects->find($id) ?? $current;
        });
    }

    /**
     * Null the password on the package's own users table. A host with its own
     * {@see Subjects} resolver keeps the password in its own store, which this class
     * cannot see: such a host overrides this method (or binds its own
     * {@see MailboxProof}) to clear it.
     *
     * Through the query builder, not the model: the `hashed` cast has nothing to say about
     * a null, and a password-change hook is not asked to approve a credential being taken
     * away.
     */
    protected function removePassword(string $subjectId): bool
    {
        if (! $this->subjects instanceof DatabaseSubjects) {
            return false;
        }

        return $this->userModel()::query()
            ->whereKey($subjectId)
            ->whereNotNull('password')
            ->toBase()
            ->update(['password' => null]) > 0;
    }

    /** Serialize concurrent claims of the same account on the default store. */
    private function lock(string $subjectId): void
    {
        if ($this->subjects instanceof DatabaseSubjects) {
            $this->userModel()::query()->whereKey($subjectId)->lockForUpdate()->first();
        }
    }

    /**
     * Organization-owned rows, read across every organization the account was in, so the
     * tenant scope is suspended for exactly these two writes.
     */
    private function revokeApiTokens(string $subjectId): int
    {
        return $this->tenant()->withoutScope(static fn (): int => UserApiToken::query()
            ->where('user_id', $subjectId)
            ->whereNull('revoked_at')
            ->toBase()
            ->update(['revoked_at' => now(), 'updated_at' => now()])
            + CustomerApiKey::query()
                ->where('user_id', $subjectId)
                ->whereNull('revoked_at')
                ->toBase()
                ->update(['revoked_at' => now(), 'updated_at' => now()]));
    }

    /** @param  Builder<covariant Model>  $query */
    private function delete(Builder $query): int
    {
        return $query->toBase()->delete();
    }

    /** @return class-string<User> */
    private function userModel(): string
    {
        $configured = config('cbox-id.models.user');

        return is_string($configured) && is_a($configured, User::class, true) ? $configured : User::class;
    }
}
