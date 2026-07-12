<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Validators;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

/**
 * Routes an assertion to the validator registered for the connection's type
 * (OIDC, SAML, …). A type with no registered validator is rejected rather than
 * silently trusted.
 */
final class DispatchingAssertionValidator implements AssertionValidator
{
    /**
     * @param  array<string, AssertionValidator>  $validators  keyed by ConnectionType value
     */
    public function __construct(private readonly array $validators) {}

    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal
    {
        $validator = $this->validators[$connection->type->value] ?? null;

        if ($validator === null) {
            throw InvalidAssertion::make("no validator registered for connection type [{$connection->type->value}]");
        }

        return $validator->validate($connection, $rawResponse);
    }
}
