<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use RuntimeException;

/**
 * A credential was refused because it does not satisfy the tenant's authentication
 * policy. The message names the rule that failed so the caller can tell the person what
 * to do differently — a refusal with no reason just gets retried.
 */
class PolicyViolation extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function tooShort(int $minLength): self
    {
        return (new self("The password must be at least {$minLength} characters."))->withSourceMessage(new SourceMessage('The password must be at least :minLength characters.', ['minLength' => $minLength]));
    }

    public static function breached(): self
    {
        return (new self('That password has appeared in a public data breach — choose another.'))->withSourceMessage(new SourceMessage('That password has appeared in a public data breach — choose another.', []));
    }

    public static function reused(int $history): self
    {
        return (new self("That password was used recently — it cannot match the last {$history}."))->withSourceMessage(new SourceMessage('That password was used recently — it cannot match the last :history.', ['history' => $history]));
    }

    public static function passwordLoginDisabled(): self
    {
        return (new self('This organization signs in through its identity provider; password sign-in is disabled.'))->withSourceMessage(new SourceMessage('This organization signs in through its identity provider; password sign-in is disabled.', []));
    }
}
