<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Enums;

/**
 * How much existing access an administrative password change invalidates.
 *
 * The blast radius is the administrator's call, not a fixed policy: recovering a
 * locked-out colleague's access is a different situation from cutting off a suspected
 * compromise, and the console asks which one this is.
 */
enum PasswordRevocationScope: string
{
    /** Sign the subject out everywhere AND kill their OAuth refresh tokens. */
    case SessionsAndTokens = 'sessions_and_tokens';

    /** Sign the subject out of interactive sessions; leave OAuth grants alive. */
    case SessionsOnly = 'sessions_only';

    /** Change the credential only; existing sessions and grants continue. */
    case Nothing = 'nothing';
}
