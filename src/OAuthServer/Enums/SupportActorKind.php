<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * In which capacity somebody starts a support session.
 */
enum SupportActorKind: string
{
    /**
     * The app vendor's staff. Authorized by the framework: the actor must hold the app's
     * own `support:impersonate` permission through an environment-wide grant.
     */
    case Staff = 'staff';

    /**
     * An environment administrator, from the console. Authorized by the CALLER — the
     * framework cannot know who administers an environment, so the host asserts it by
     * passing this kind, exactly as it asserts the environment plane everywhere else.
     */
    case EnvironmentAdmin = 'environment_admin';
}
