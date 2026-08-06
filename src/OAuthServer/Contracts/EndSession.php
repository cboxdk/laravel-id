<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\ValueObjects\EndSessionRequest;
use Cbox\Id\OAuthServer\ValueObjects\EndSessionResult;

/**
 * Resolves an RP-initiated logout request (OpenID Connect RP-Initiated Logout 1.0)
 * into a safe outcome: the subject the logout concerns and the one validated
 * post-logout redirect (if any). Deny-by-default — an unregistered or mismatched
 * `post_logout_redirect_uri` yields no redirect, never a trusted-looking one.
 */
interface EndSession
{
    public function resolve(EndSessionRequest $request): EndSessionResult;
}
