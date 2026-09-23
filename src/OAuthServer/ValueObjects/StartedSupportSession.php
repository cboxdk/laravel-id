<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\SupportSession;

/**
 * A support session that has begun, plus the first authorization code for it when the
 * caller supplied a {@see SupportCodeRequest}. The raw code exists only here; the
 * database holds its hash.
 */
readonly class StartedSupportSession
{
    public function __construct(
        public SupportSession $session,
        public ?string $code = null,
    ) {}
}
