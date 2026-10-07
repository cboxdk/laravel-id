<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\AuthorizationCode;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\Models\SessionParticipant;

/**
 * Every OAuth grant the subject holds, through the same {@see SubjectGrantRevoker} a
 * deactivation uses — refresh tokens withdrawn (the applications told), access tokens in
 * flight revoked — then every pending flow that could still mint a new one deleted:
 * unredeemed authorization codes, device codes and CIBA requests.
 *
 * Session participation rows go last. They are what back-channel logout fans out over,
 * and the sessions step (which runs earlier) has already used them.
 */
class OAuthGrantsErasureStep implements ErasureStep
{
    public function __construct(
        private readonly SubjectGrantRevoker $grants,
    ) {}

    public function name(): string
    {
        return 'oauth.grants';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $id = $request->subjectId;

        $refreshTokens = RefreshToken::query()->where('user_id', $id)->whereNull('revoked_at')->count();
        $accessTokens = AccessToken::query()->where('user_id', $id)->whereNull('revoked_at')->count();

        $this->grants->revokeGrantsForUser($id);

        return ErasureStepResult::of($this->name(), [
            'refresh_tokens_revoked' => $refreshTokens,
            'access_tokens_revoked' => $accessTokens,
            'authorization_codes' => AuthorizationCode::query()->where('user_id', $id)->toBase()->delete(),
            'device_codes' => DeviceCode::query()->where('user_id', $id)->toBase()->delete(),
            'ciba_requests' => BackchannelAuthRequest::query()->where('user_id', $id)->toBase()->delete(),
            'session_participants' => SessionParticipant::query()->where('user_id', $id)->toBase()->delete(),
        ]);
    }
}
