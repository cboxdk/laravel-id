<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\CibaClientNotifications;
use Cbox\Id\OAuthServer\Jobs\NotifyCibaClient;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\ValueObjects\BackchannelAuthenticationResult;

/**
 * Pings are a queued job ({@see NotifyCibaClient}) with a short timeout and retries, off
 * the request that approved: the person tapping Approve never waits on the client's server.
 */
class QueuedCibaClientNotifications implements CibaClientNotifications
{
    public function remember(BackchannelAuthenticationResult $result, string $clientNotificationToken): void
    {
        BackchannelAuthRequest::query()->whereKey($result->requestId)->first()?->forceFill([
            'client_notification_token' => $clientNotificationToken,
            'notification_auth_req_id' => $result->authReqId,
        ])->save();
    }

    public function notify(string $requestId): void
    {
        $request = BackchannelAuthRequest::query()->whereKey($requestId)->first();

        if ($request === null || $request->getRawOriginal('client_notification_token') === null) {
            return;
        }

        NotifyCibaClient::dispatch($request->environment_id, $request->id);
    }
}
