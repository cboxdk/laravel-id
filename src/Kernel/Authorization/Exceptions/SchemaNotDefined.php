<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/**
 * The environment has no authorization schema yet, so there is nothing a tuple could be
 * checked against. Define one first.
 */
final class SchemaNotDefined extends AuthorizationModelException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public function __construct()
    {
        $this->withSourceMessage(new SourceMessage('This environment has no authorization schema yet. Define one first.'));
        parent::__construct('This environment has no authorization schema yet. Define one first.');
    }

    public function errorCode(): string
    {
        return 'schema_not_defined';
    }
}
