<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure\Steps;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Contracts\SubjectPseudonymiser;
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
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Every credential and credential artefact the Identity module keeps for the subject —
 * DELETED, not disabled: passkeys, the TOTP factor and its recovery codes, the password
 * history and age, a pending forced change, outstanding reset / verification / magic
 * link tokens, the lockout counter, and the links to external identity providers (whose
 * `raw` claims are the provider's copy of the person).
 *
 * The password hash itself lives on the subject row and is dropped by the
 * {@see SubjectPseudonymiser}.
 */
class CredentialsErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'identity.credentials';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $id = $request->subjectId;

        $counts = [
            'passkeys' => $this->delete(WebAuthnCredential::query()->where('user_id', $id)),
            'mfa_factors' => $this->delete(MfaFactor::query()->where('user_id', $id)),
            'recovery_codes' => $this->delete(MfaRecoveryCode::query()->where('user_id', $id)),
            'password_history' => $this->delete(PasswordHistoryEntry::query()->where('user_id', $id)),
            'password_ages' => $this->delete(PasswordAge::query()->where('user_id', $id)),
            'password_change_requirements' => $this->delete(PasswordChangeRequirement::query()->where('user_id', $id)),
            'email_verification_tokens' => $this->delete(EmailVerificationToken::query()->where('user_id', $id)),
            'login_attempt_counters' => $this->delete(LoginAttemptCounter::query()->where('user_id', $id)),
            'federated_identities' => $this->delete(IdentityLink::query()->where('user_id', $id)),
            'password_reset_tokens' => 0,
            'magic_links' => 0,
        ];

        // The two token stores keyed by ADDRESS, not by subject.
        if ($request->email !== null) {
            $email = mb_strtolower($request->email);
            $counts['password_reset_tokens'] = $this->delete(PasswordResetToken::query()->whereRaw('lower(email) = ?', [$email]));
            $counts['magic_links'] = $this->delete(MagicLinkToken::query()->whereRaw('lower(email) = ?', [$email]));
        }

        return ErasureStepResult::of($this->name(), $counts);
    }

    /** @param  Builder<covariant Model>  $query */
    private function delete(Builder $query): int
    {
        return $query->toBase()->delete();
    }
}
