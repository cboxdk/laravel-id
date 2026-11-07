<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use Cbox\Id\OAuthServer\Enums\ClientSecretRefusal;
use RuntimeException;

/**
 * A rotation or revocation the client's credential model does not allow. {@see $reason}
 * says which; the message is written for the person who asked.
 */
class ClientSecretRefused extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public function __construct(public readonly ClientSecretRefusal $reason, string $message)
    {
        parent::__construct($message);
    }

    public static function publicClient(string $clientId): self
    {
        return (new self(ClientSecretRefusal::PublicClient, "Client [{$clientId}] is public: it uses PKCE and has no secret."))->withSourceMessage(new SourceMessage('Client [:clientId] is public: it uses PKCE and has no secret.', ['clientId' => $clientId]));
    }

    public static function signsAssertions(string $clientId): self
    {
        return (new self(ClientSecretRefusal::SignsAssertions, "Client [{$clientId}] authenticates with its own keys (private_key_jwt) and has no secret. Rotate the key in its JWK Set instead."))->withSourceMessage(new SourceMessage('Client [:clientId] authenticates with its own keys (private_key_jwt) and has no secret. Rotate the key in its JWK Set instead.', ['clientId' => $clientId]));
    }

    public static function lastLiveSecret(string $clientId): self
    {
        return (new self(ClientSecretRefusal::LastLiveSecret, "That is the last live secret of client [{$clientId}]. Rotate the secret to replace it instead; revoking it would leave the client unable to authenticate."))->withSourceMessage(new SourceMessage('That is the last live secret of client [:clientId]. Rotate the secret to replace it instead; revoking it would leave the client unable to authenticate.', ['clientId' => $clientId]));
    }

    public static function graceOutOfRange(int $grace, int $max): self
    {
        return (new self(ClientSecretRefusal::GraceOutOfRange, "A rotation grace period must be between 0 and {$max} seconds; {$grace} was given."))->withSourceMessage(new SourceMessage('A rotation grace period must be between 0 and :max seconds; :grace was given.', ['max' => $max, 'grace' => $grace]));
    }

    public static function unknownSecret(string $clientId, string $secretId): self
    {
        return (new self(ClientSecretRefusal::UnknownSecret, "Client [{$clientId}] has no live secret [{$secretId}]."))->withSourceMessage(new SourceMessage('Client [:clientId] has no live secret [:secretId].', ['clientId' => $clientId, 'secretId' => $secretId]));
    }
}
