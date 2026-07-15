<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Exceptions;

use RuntimeException;

/**
 * A certify/revoke decision was attempted on a campaign that is already closed —
 * decisions are only accepted while the campaign is open.
 */
final class CampaignClosed extends RuntimeException
{
    public static function forId(string $campaignId): self
    {
        return new self(sprintf('Governance campaign [%s] is closed.', $campaignId));
    }
}
