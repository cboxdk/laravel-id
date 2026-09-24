<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use Cbox\Id\OAuthServer\Enums\SupportSessionRefusal;
use RuntimeException;

/**
 * A support session that could not be started, or a code for one that could not be
 * minted. `$refusal` names which check failed.
 */
class SupportSessionRefused extends RuntimeException
{
    public function __construct(public readonly SupportSessionRefusal $refusal)
    {
        parent::__construct($refusal->message());
    }

    public static function because(SupportSessionRefusal $refusal): self
    {
        return new self($refusal);
    }
}
