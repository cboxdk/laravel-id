<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Exceptions;

use RuntimeException;

class UnknownCampaign extends RuntimeException
{
    public static function forId(string $campaignId): self
    {
        return new self(sprintf('No governance campaign [%s] in this environment.', $campaignId));
    }
}
