<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Presentation\Contracts;

use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/** Optional presentation metadata; protocol error codes and messages remain unchanged. */
interface HasSourceMessage
{
    public function sourceMessage(): ?SourceMessage;
}
