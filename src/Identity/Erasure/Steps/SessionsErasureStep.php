<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure\Steps;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;

/**
 * Every sign-in session: revoked through the {@see SessionManager} (so the relying
 * parties it signed the person in to get their back-channel logout), and stripped of the
 * IP address and user agent each row recorded — both personal data, neither needed once
 * the session can never be used again.
 *
 * The rows themselves stay, keyed by the opaque id, because the audit trail names them.
 */
class SessionsErasureStep implements ErasureStep
{
    public function __construct(
        private readonly SessionManager $sessions,
    ) {}

    public function name(): string
    {
        return 'identity.sessions';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $active = Session::query()->where('user_id', $request->subjectId)->whereNull('revoked_at')->count();

        $this->sessions->revokeAllForUser($request->subjectId);

        $scrubbed = Session::query()
            ->where('user_id', $request->subjectId)
            ->where(static function ($query): void {
                $query->whereNotNull('ip')->orWhereNotNull('user_agent');
            })
            ->update(['ip' => null, 'user_agent' => null]);

        return ErasureStepResult::of($this->name(), [
            'sessions_revoked' => $active,
            'sessions_scrubbed' => (int) $scrubbed,
        ]);
    }
}
