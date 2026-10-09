<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use InvalidArgumentException;

/**
 * A pipe configuration the platform refuses to store: a provider the catalogue does not
 * have, a parameter that does not match its pattern, a malformed scope, or a client id /
 * secret that is blank. The message is safe to show an administrator — it never repeats
 * the secret — and `field` names the input it is about (`provider`, `client_id`,
 * `client_secret`, `scopes`, `parameters`), so a form can put it in the right place.
 */
class InvalidPipeConfiguration extends InvalidArgumentException
{
    public function __construct(string $message, public readonly string $field = 'parameters')
    {
        parent::__construct($message);
    }

    public static function unknownProvider(string $provider): self
    {
        return new self("There is no pipe provider [{$provider}].", 'provider');
    }

    public static function alreadyConfigured(string $provider): self
    {
        return new self("A {$provider} pipe is already configured in this environment.", 'provider');
    }

    public static function parameter(string $provider, string $parameter): self
    {
        return new self("The [{$parameter}] value is not valid for the {$provider} pipe.", 'parameters');
    }

    public static function scope(string $scope): self
    {
        return new self("The scope [{$scope}] is not a valid OAuth scope.", 'scopes');
    }

    /** @param  'client_id'|'client_secret'  $field */
    public static function blank(string $field): self
    {
        $label = $field === 'client_id' ? 'client ID' : 'client secret';

        return new self("The pipe's {$label} must not be empty.", $field);
    }
}
