<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use Cbox\Id\OAuthServer\Enums\SupportSessionRefusal;
use RuntimeException;

/**
 * A support session that could not be started, or a code for one that could not be
 * minted. `$refusal` names which check failed.
 */
class SupportSessionRefused extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public function __construct(public readonly SupportSessionRefusal $refusal)
    {
        parent::__construct($refusal->message());
        $this->withSourceMessage(new SourceMessage($refusal->message()));
    }

    public static function because(SupportSessionRefusal $refusal): self
    {
        return new self($refusal);
    }
}
