<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use InvalidArgumentException;

/** A source-owned provisioning refusal with optional host presentation metadata. */
class InvalidTenantProvisioning extends InvalidArgumentException implements HasSourceMessage
{
    use CarriesSourceMessage;
}
