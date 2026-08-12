<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Carbon\CarbonInterface;

/**
 * An application a person has authorized, as THEY need to see it.
 *
 * WHY THIS EXISTS AS A VALUE OBJECT rather than as refresh-token rows. A person does not
 * have "four refresh tokens for the CLI"; they have "the CLI can act as me". Rotation
 * mints a new row on every use, so the rows are an implementation detail of freshness —
 * handing them to a screen would show somebody eleven identical entries for one approval
 * and ask them to work out which to revoke. One row per CLIENT is the fact they can act
 * on.
 *
 * `scopes` is the union of what was granted, because that is the honest answer to "what
 * can it do": a client that asked for `openid` once and `offline_access profile` later can
 * do both, and showing only the newest grant would understate it.
 */
readonly class ConnectedApplication
{
    /**
     * @param  list<string>  $scopes  the union of every live grant's scopes
     */
    public function __construct(
        public string $clientId,
        public string $name,
        public array $scopes,
        public ?string $organizationId,
        public ?CarbonInterface $firstAuthorizedAt,
        public ?CarbonInterface $lastUsedAt,
    ) {}

    /** Whether this application can act while nobody is at the keyboard. */
    public function actsOffline(): bool
    {
        return in_array('offline_access', $this->scopes, true);
    }
}
