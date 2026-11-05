<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Kernel\Crypto\ValueObjects\TotpEnrollment;

readonly class TotpDeviceEnrollment extends TotpEnrollment
{
    public function __construct(public string $id, string $secret, string $provisioningUri)
    {
        parent::__construct($secret, $provisioningUri);
    }
}
