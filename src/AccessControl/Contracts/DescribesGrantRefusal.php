<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/** Optional metadata from the last refuse() call; never a replacement for the veto. */
interface DescribesGrantRefusal extends GrantGuard
{
    public function lastRefusalMessage(): ?SourceMessage;
}
