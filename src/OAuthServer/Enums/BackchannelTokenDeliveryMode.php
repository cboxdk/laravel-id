<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * How a client registered for CIBA learns that the person answered (CIBA Core §5).
 *
 * `poll` — the default, and what every client had before this existed: the client asks the
 * token endpoint every `interval` seconds until it gets a token or an error.
 *
 * `ping` — on approve or deny, Cbox ID POSTs `{"auth_req_id": "…"}` to the client's
 * registered `backchannel_client_notification_endpoint`, authorized with the
 * `client_notification_token` the client sent with the request; the client then calls
 * the token endpoint once. Push mode (the token in the callback) is not offered.
 */
enum BackchannelTokenDeliveryMode: string
{
    case Poll = 'poll';
    case Ping = 'ping';
}
