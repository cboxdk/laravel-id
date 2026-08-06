<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * A service account's lifecycle status. `Retired` is an access-revocation state — a
 * retired account must never mint or exchange credentials again — so it is an enum
 * rather than a raw string, keeping the revocation check typo-proof and exhaustive.
 */
enum ServiceAccountStatus: string
{
    case Active = 'active';
    case Retired = 'retired';
}
