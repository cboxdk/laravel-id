<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Enums\BackchannelTokenDeliveryMode;
use Cbox\Id\OAuthServer\ValueObjects\BackchannelAuthenticationResult;

/**
 * CIBA ping mode (CIBA Core §10.2): tell a client that the person answered.
 *
 * A separate contract from {@see BackchannelAuthentication} so that a host decorating that
 * one (a mailer, a push sender) keeps compiling: ping is delivery, not the state machine.
 * The backchannel endpoint calls {@see remember()} for a ping-mode client's request; the
 * state machine calls {@see notify()} on every approve and deny, and nothing happens for a
 * request that has nothing remembered.
 */
interface CibaClientNotifications
{
    /**
     * Keep what the ping needs for this request: the client's `client_notification_token`
     * and its own auth_req_id, both encrypted at rest and cleared once spent.
     */
    public function remember(BackchannelAuthenticationResult $result, string $clientNotificationToken): void;

    /**
     * Queue the ping for a request the person has just approved or denied. A no-op for a
     * request that is not a ping-mode one ({@see BackchannelTokenDeliveryMode}).
     */
    public function notify(string $requestId): void;
}
