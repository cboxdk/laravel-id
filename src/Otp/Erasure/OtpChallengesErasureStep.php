<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Otp\Models\OtpChallenge;

/**
 * One-time-code challenges sent to the subject's email address. Keyed by recipient, not
 * by subject, so only the address the subject store knew is matched; a challenge to a
 * phone number the package was never told belongs to them stays until it is pruned.
 */
class OtpChallengesErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'otp.challenges';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $deleted = $request->email === null ? 0 : OtpChallenge::query()
            ->whereRaw('lower(recipient) = ?', [mb_strtolower($request->email)])
            ->toBase()->delete();

        return ErasureStepResult::of($this->name(), ['otp_challenges' => $deleted]);
    }
}
