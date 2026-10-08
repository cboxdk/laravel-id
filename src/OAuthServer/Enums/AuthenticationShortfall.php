<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;

/**
 * Why an authentication does not meet an {@see AuthenticationRequirement}.
 *
 * Two answers, because the person has to do two different things about them: a login that
 * is too OLD is fixed by signing in again, and one that is too WEAK by adding a factor. An
 * authorization endpoint routes them differently (re-login vs. step-up screen), and a
 * client reading the error tells them apart (`login_required` vs.
 * `unmet_authentication_requirements`).
 */
enum AuthenticationShortfall: string
{
    /**
     * `max_age` was exceeded — or the authentication cannot be dated at all, which is
     * treated the same way: a login nobody can put a time on is not provably recent.
     */
    case TooOld = 'too_old';

    /**
     * The requested `acr` was not achieved — or nothing says what was achieved, which is
     * likewise not evidence that it was.
     */
    case ContextNotMet = 'context_not_met';
}
