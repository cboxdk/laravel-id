<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A client ID metadata document (draft-ietf-oauth-client-id-metadata-document) could not
 * be used: it could not be fetched, or it was fetched and says something this server will
 * not accept.
 *
 * `$reason` is a stable, machine-readable code — the tests and the host's error page key
 * on it — and the message is for the developer of the client. The OAuth error a host
 * shows is always `invalid_client` ({@see $error}): until the document checks out there
 * is no verified redirect URI, so RFC 6749 §4.1.2.1 forbids redirecting the error back,
 * and the host renders it instead.
 */
class InvalidClientMetadataDocument extends RuntimeException
{
    public readonly string $error;

    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
        $this->error = 'invalid_client';
    }

    public static function disabled(): self
    {
        return new self('disabled', 'Client ID metadata documents are not accepted by this authorization server.');
    }

    public static function invalidClientId(string $clientId): self
    {
        return new self('invalid_client_id', "The client_id [{$clientId}] is not a valid client ID metadata document URL: it must be an https URL with a path, no fragment, no credentials and no dot segments, at most 255 characters.");
    }

    public static function unsafeUrl(string $detail): self
    {
        return new self('unsafe_url', "The client ID metadata document URL was refused: {$detail}");
    }

    public static function fetchFailed(string $detail): self
    {
        return new self('fetch_failed', "The client ID metadata document could not be fetched: {$detail}");
    }

    public static function tooLarge(int $limit): self
    {
        return new self('too_large', "The client ID metadata document is larger than {$limit} bytes.");
    }

    public static function notJson(): self
    {
        return new self('invalid_json', 'The client ID metadata document is not a JSON object.');
    }

    public static function clientIdMismatch(): self
    {
        return new self('client_id_mismatch', 'The client_id in the metadata document is not the URL it was fetched from.');
    }

    public static function prohibitedField(string $field): self
    {
        return new self('prohibited_field', "A client ID metadata document must not contain [{$field}]: the client has no shared secret.");
    }

    public static function field(string $field, string $requirement): self
    {
        return new self('invalid_field', "The metadata document's [{$field}] {$requirement}.");
    }

    public static function redirectUri(string $uri): self
    {
        return new self('invalid_redirect_uri', "The redirect URI [{$uri}] must be an https URL, or http on a loopback host, with no fragment.");
    }

    public static function authMethod(string $method): self
    {
        return new self('invalid_auth_method', "token_endpoint_auth_method [{$method}] is not accepted for a metadata document client: use \"none\" or \"private_key_jwt\" with a jwks_uri.");
    }
}
