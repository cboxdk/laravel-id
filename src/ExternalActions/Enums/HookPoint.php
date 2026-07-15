<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Enums;

/**
 * The named points where the platform pauses to consult external logic (an inline
 * hook). v1 ships one: TokenMinting — run just before an access token is signed, so
 * an action can enrich the token's claims or veto issuance. More points (pre-login,
 * pre-registration) are natural extensions; see docs/core-concepts/external-actions.md.
 */
enum HookPoint: string
{
    // The value doubles as a config key (external_actions.hooks.<value>), so it uses
    // an underscore — a dot would collide with Laravel's config dot-notation and
    // never match a literal array key.
    case TokenMinting = 'token_minting';
}
