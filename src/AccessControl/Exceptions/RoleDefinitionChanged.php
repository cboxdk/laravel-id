<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use RuntimeException;

class RoleDefinitionChanged extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public function __construct()
    {
        $this->withSourceMessage(new SourceMessage('The pending role definition has changed or is no longer available. Review it again before activating.'));
        parent::__construct('The pending role definition has changed or is no longer available. Review it again before activating.');
    }
}
