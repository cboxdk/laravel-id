<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use InvalidArgumentException;

/**
 * An API (resource server) or one of its scopes could not be registered as described.
 * The message names the field and the reason, for the console or management API to show.
 */
class InvalidApiDefinition extends InvalidArgumentException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function identifier(string $identifier): self
    {
        return (new self("The API identifier [{$identifier}] must be an absolute URI with a host and no fragment (RFC 8707), at most 255 characters."))->withSourceMessage(new SourceMessage('The API identifier [:identifier] must be an absolute URI with a host and no fragment (RFC 8707), at most 255 characters.', ['identifier' => $identifier]));
    }

    public static function identifierTaken(string $identifier): self
    {
        return (new self("An API with the identifier [{$identifier}] is already registered in this environment."))->withSourceMessage(new SourceMessage('An API with the identifier [:identifier] is already registered in this environment.', ['identifier' => $identifier]));
    }

    public static function name(): self
    {
        return (new self('An API needs a name of 1 to 120 characters.'))->withSourceMessage(new SourceMessage('An API needs a name of 1 to 120 characters.', []));
    }

    public static function scopeKey(string $key): self
    {
        return (new self("The scope [{$key}] is not a valid scope token (RFC 6749 §3.3: printable ASCII, no spaces, quotes or backslashes, at most 128 characters)."))->withSourceMessage(new SourceMessage('The scope [:key] is not a valid scope token (RFC 6749 §3.3: printable ASCII, no spaces, quotes or backslashes, at most 128 characters).', ['key' => $key]));
    }

    public static function reservedScope(string $key): self
    {
        return (new self("The scope [{$key}] is defined by the authorization server itself and cannot belong to an API."))->withSourceMessage(new SourceMessage('The scope [:key] is defined by the authorization server itself and cannot belong to an API.', ['key' => $key]));
    }

    public static function declaredScope(string $key): self
    {
        return (new self("The scope [{$key}] is already accepted by a resource this server declares itself. Pick a key of the API's own, such as one prefixed with its name."))->withSourceMessage(new SourceMessage('The scope [:key] is already accepted by a resource this server declares itself. Pick a key of the API\'s own, such as one prefixed with its name.', ['key' => $key]));
    }

    public static function scopeTaken(string $key): self
    {
        return (new self("The scope [{$key}] already belongs to another API in this environment. Scope keys are unique per environment, because a token request names a scope by key alone."))->withSourceMessage(new SourceMessage('The scope [:key] already belongs to another API in this environment. Scope keys are unique per environment, because a token request names a scope by key alone.', ['key' => $key]));
    }

    public static function unknownClient(string $clientId): self
    {
        return (new self("No app with the client id [{$clientId}] exists in this environment."))->withSourceMessage(new SourceMessage('No app with the client id [:clientId] exists in this environment.', ['clientId' => $clientId]));
    }

    public static function clientOwnership(string $clientId): self
    {
        return (new self("The app [{$clientId}] must have the same owner as the API it enforces. Linking it would stamp one owner's roles and permissions into another owner's tokens."))->withSourceMessage(new SourceMessage('The app [:clientId] must have the same owner as the API it enforces. Linking it would stamp one owner\'s roles and permissions into another owner\'s tokens.', ['clientId' => $clientId]));
    }
}
