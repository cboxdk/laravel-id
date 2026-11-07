<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use InvalidArgumentException;

/**
 * A pipe configuration the platform refuses to store: a provider the catalogue does not
 * have, a parameter that does not match its pattern, a malformed scope, or a client id /
 * secret that is blank. The message is safe to show an administrator — it never repeats
 * the secret — and `field` names the input it is about (`provider`, `client_id`,
 * `client_secret`, `scopes`, `parameters`), so a form can put it in the right place.
 */
class InvalidPipeConfiguration extends InvalidArgumentException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public function __construct(string $message, public readonly string $field = 'parameters')
    {
        parent::__construct($message);
    }

    public static function unknownProvider(string $provider): self
    {
        return (new self("There is no pipe provider [{$provider}].", 'provider'))->withSourceMessage(new SourceMessage('There is no pipe provider [:provider].', ['provider' => $provider]));
    }

    public static function alreadyConfigured(string $provider): self
    {
        return (new self("A {$provider} pipe is already configured in this environment.", 'provider'))->withSourceMessage(new SourceMessage('A :provider pipe is already configured in this environment.', ['provider' => $provider]));
    }

    public static function parameter(string $provider, string $parameter): self
    {
        return (new self("The [{$parameter}] value is not valid for the {$provider} pipe.", 'parameters'))->withSourceMessage(new SourceMessage('The [:parameter] value is not valid for the :provider pipe.', ['parameter' => $parameter, 'provider' => $provider]));
    }

    public static function scope(string $scope): self
    {
        return (new self("The scope [{$scope}] is not a valid OAuth scope.", 'scopes'))->withSourceMessage(new SourceMessage('The scope [:scope] is not a valid OAuth scope.', ['scope' => $scope]));
    }

    /** @param  'client_id'|'client_secret'  $field */
    public static function blank(string $field): self
    {
        $label = $field === 'client_id' ? 'client ID' : 'client secret';

        return (new self("The pipe's {$label} must not be empty.", $field))->withSourceMessage(new SourceMessage($field === 'client_id' ? "The pipe's client ID must not be empty." : "The pipe's client secret must not be empty."));
    }
}
