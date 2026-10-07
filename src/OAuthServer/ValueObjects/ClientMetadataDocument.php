<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\Support\ClientIdUrl;
use Cbox\Id\OAuthServer\Support\WebRedirectUri;

/**
 * A client ID metadata document (draft-ietf-oauth-client-id-metadata-document) that has
 * been checked against the URL it was fetched from.
 *
 * WHAT IS VERIFIED, AND WHAT IS NOT. Fetching the document over https from the
 * `client_id` URL proves one thing: whoever controls that host published these redirect
 * URIs. It proves nothing about the name or the logo, which the publisher writes freely —
 * so a consent screen leads with the HOST, and the name is decoration.
 *
 * THE RULES, each refused with a stable reason code:
 *  - the document's `client_id` is exactly the URL it was fetched from — otherwise any
 *    host could serve a copy of another client's document;
 *  - no `client_secret` / `client_secret_expires_at` — a document is public, so a secret
 *    in it is no secret;
 *  - `token_endpoint_auth_method` is `none` (the default here) or `private_key_jwt` with an
 *    https `jwks_uri` — never a shared-secret method;
 *  - `redirect_uris` is a non-empty list of https URIs, or http on a loopback host
 *    ({@see WebRedirectUri}), matched EXACTLY at `/authorize`;
 *  - `grant_types`, when given, includes `authorization_code`; only it and `refresh_token`
 *    are kept. `response_types`, when given, includes `code`.
 *
 * Never constructed from unvalidated input except through {@see fromArray()}; the
 * zero-argument-style constructor exists so tests and fakes can build one directly.
 */
readonly class ClientMetadataDocument
{
    /** The grants a metadata document client may use: the code flow and its refresh. */
    public const GRANT_TYPES = ['authorization_code', 'refresh_token'];

    private const PROHIBITED = ['client_secret', 'client_secret_expires_at'];

    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $grantTypes
     * @param  list<string>|null  $scopes  null = the document named no scope
     */
    public function __construct(
        public string $clientId,
        public array $redirectUris,
        public ?string $clientName = null,
        public array $grantTypes = self::GRANT_TYPES,
        public ?array $scopes = null,
        public string $tokenEndpointAuthMethod = 'none',
        public ?string $jwksUri = null,
        public ?string $clientUri = null,
        public ?string $logoUri = null,
    ) {}

    /**
     * @param  array<string, mixed>  $data  the decoded document
     *
     * @throws InvalidClientMetadataDocument
     */
    public static function fromArray(array $data, string $fetchedFrom): self
    {
        foreach (self::PROHIBITED as $field) {
            if (array_key_exists($field, $data)) {
                throw InvalidClientMetadataDocument::prohibitedField($field);
            }
        }

        // Exact, byte for byte. Normalising either side (trailing slash, case) would let a
        // document claim a client id it was not fetched from.
        if (($data['client_id'] ?? null) !== $fetchedFrom) {
            throw InvalidClientMetadataDocument::clientIdMismatch();
        }

        $method = $data['token_endpoint_auth_method'] ?? 'none';

        if (! is_string($method) || ! in_array($method, ['none', 'private_key_jwt'], true)) {
            throw InvalidClientMetadataDocument::authMethod(is_string($method) ? $method : get_debug_type($method));
        }

        $jwksUri = self::optionalString($data, 'jwks_uri');

        if ($method === 'private_key_jwt' && ($jwksUri === null || ! ClientIdUrl::isValid($jwksUri))) {
            throw InvalidClientMetadataDocument::field('jwks_uri', 'must be an https URL when token_endpoint_auth_method is "private_key_jwt"');
        }

        // Inline keys are not read: a client whose keys rotate publishes them at jwks_uri,
        // and a document carrying both would leave which one counts to guesswork.
        if (array_key_exists('jwks', $data)) {
            throw InvalidClientMetadataDocument::field('jwks', 'is not accepted; publish the key set at jwks_uri');
        }

        return new self(
            clientId: $fetchedFrom,
            redirectUris: self::redirectUris($data['redirect_uris'] ?? null),
            clientName: self::optionalString($data, 'client_name'),
            grantTypes: self::grantTypes($data),
            scopes: self::scopes($data),
            tokenEndpointAuthMethod: $method,
            jwksUri: $method === 'private_key_jwt' ? $jwksUri : null,
            clientUri: self::optionalUrl($data, 'client_uri'),
            logoUri: self::optionalUrl($data, 'logo_uri'),
        );
    }

    public function host(): string
    {
        return ClientIdUrl::host($this->clientId);
    }

    public function refreshes(): bool
    {
        return in_array('refresh_token', $this->grantTypes, true);
    }

    /**
     * The validated document as JSON-shaped data — what is cached, so a cached entry is
     * re-validated by {@see fromArray()} on the way back out rather than trusted.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'client_id' => $this->clientId,
            'redirect_uris' => $this->redirectUris,
            'client_name' => $this->clientName,
            'grant_types' => $this->grantTypes,
            'scope' => $this->scopes === null ? null : implode(' ', $this->scopes),
            'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            'jwks_uri' => $this->jwksUri,
            'client_uri' => $this->clientUri,
            'logo_uri' => $this->logoUri,
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @return list<string>
     *
     * @throws InvalidClientMetadataDocument
     */
    private static function redirectUris(mixed $value): array
    {
        if (! is_array($value) || $value === [] || ! array_is_list($value)) {
            throw InvalidClientMetadataDocument::field('redirect_uris', 'must be a non-empty array of URIs');
        }

        $uris = [];

        foreach ($value as $uri) {
            if (! is_string($uri) || ! WebRedirectUri::isValid($uri)) {
                throw InvalidClientMetadataDocument::redirectUri(is_string($uri) ? $uri : get_debug_type($uri));
            }

            $uris[] = $uri;
        }

        return array_values(array_unique($uris));
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<string>
     *
     * @throws InvalidClientMetadataDocument
     */
    private static function grantTypes(array $data): array
    {
        if (array_key_exists('response_types', $data)) {
            $responseTypes = $data['response_types'];

            if (! is_array($responseTypes) || ! in_array('code', $responseTypes, true)) {
                throw InvalidClientMetadataDocument::field('response_types', 'must include "code"');
            }
        }

        if (! array_key_exists('grant_types', $data)) {
            return self::GRANT_TYPES;
        }

        $declared = $data['grant_types'];

        if (! is_array($declared) || ! in_array('authorization_code', $declared, true)) {
            throw InvalidClientMetadataDocument::field('grant_types', 'must include "authorization_code"');
        }

        // Kept, not refused: a document written for several servers may list grants this
        // one does not offer a metadata document client, and the client still works here
        // with the ones it does.
        return array_values(array_filter(self::GRANT_TYPES, static fn (string $grant): bool => in_array($grant, $declared, true)));
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<string>|null
     *
     * @throws InvalidClientMetadataDocument
     */
    private static function scopes(array $data): ?array
    {
        if (! array_key_exists('scope', $data)) {
            return null;
        }

        if (! is_string($data['scope'])) {
            throw InvalidClientMetadataDocument::field('scope', 'must be a space-separated string');
        }

        return array_values(array_filter(explode(' ', $data['scope']), static fn (string $scope): bool => $scope !== ''));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function optionalString(array $data, string $field): ?string
    {
        $value = $data[$field] ?? null;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * An https URL or nothing: these are shown to a person, and a `javascript:` logo or
     * home page is a link a consent screen must never render.
     *
     * @param  array<string, mixed>  $data
     */
    private static function optionalUrl(array $data, string $field): ?string
    {
        $value = self::optionalString($data, $field);

        if ($value === null) {
            return null;
        }

        $scheme = parse_url($value, PHP_URL_SCHEME);

        return is_string($scheme) && strtolower($scheme) === 'https' && filter_var($value, FILTER_VALIDATE_URL) !== false ? $value : null;
    }
}
