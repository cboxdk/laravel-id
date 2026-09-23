<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\Identity\Contracts\LogoutPropagator;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\OAuthServer\ValueObjects\AccessWithdrawal;
use Cbox\Id\OAuthServer\ValueObjects\SessionParticipation;

/**
 * OpenID Connect Back-Channel Logout 1.0: when a person's session here ends, tell every
 * application it signed them in to, server to server, so they are signed out there too.
 *
 * THE HOST'S HALF IS SMALL. Pass the session id to {@see AuthorizationCodes::issue()} when
 * minting a code, so the ID Token carries `sid` and the session is recorded against the
 * client. Ending sessions through {@see SessionManager} then notifies the applications on
 * its own; a host that ends a session some other way calls {@see sessionEnded()} or
 * {@see subjectSignedOut()} itself.
 *
 * Every method here only RECORDS and QUEUES. Delivery — signing the logout token and the
 * HTTP POST to the relying party — happens on a queue worker, with retries, so a relying
 * party that is down cannot make signing out slow or make it fail.
 */
interface BackchannelLogout extends LogoutPropagator
{
    /**
     * Record that a sign-in session signed a person in to a client. Idempotent per
     * (session, client).
     *
     * A participation with no session id is ignored: there is nothing to end it by.
     */
    public function participate(SessionParticipation $participation): void;

    /**
     * The person's access has been withdrawn — grants revoked, membership removed — so the
     * applications holding it should end the sessions they keep for them.
     */
    public function accessWithdrawn(AccessWithdrawal $withdrawal): void;
}
