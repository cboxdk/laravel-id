<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\OAuthServer\Contracts\ClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Support\ClientIdUrl;
use Cbox\Id\OAuthServer\ValueObjects\ClientMetadataDocument;
use LogicException;

/**
 * A client described by a client ID metadata document rather than registered: its
 * `client_id` is the https URL of the document, and every fact about it is read from
 * there ({@see ClientIdMetadataDocuments}).
 *
 * NEVER PERSISTED. The same document URL is the same client in every environment, while
 * `oauth_clients.client_id` is unique across the whole table — and more to the point, a
 * row would be a second copy of facts the document owns, going stale the moment the
 * publisher edits it. So the client is rebuilt from the (cached) document wherever it is
 * needed: at `/authorize`, at the token endpoint, at PAR and revocation. Codes, tokens and
 * refresh grants carry the URL as their `client_id`, exactly as they carry any other.
 * {@see save()} refuses, so nothing can write one by accident.
 *
 * SELF-REGISTERED FOR EVERY PURPOSE. {@see isDynamicallyRegistered()} is true, which is
 * what makes the scope rules treat it as the stranger it is: never environment-owned,
 * never a reserved scope, only audiences that accept self-registered clients. Consent can
 * never be skipped for it.
 */
class MetadataDocumentClient extends Client
{
    /**
     * @param  list<string>  $scopes  the scopes it may hold here, already narrowed
     * @param  array<string, mixed>|null  $jwks  the key set fetched from `jwks_uri`, for `private_key_jwt`
     */
    public static function describe(ClientMetadataDocument $document, string $environmentId, array $scopes, ?array $jwks = null): self
    {
        $client = new self;

        $client->forceFill([
            'environment_id' => $environmentId,
            'organization_id' => null,
            'client_id' => $document->clientId,
            'name' => $document->clientName ?? $document->host(),
            // `private_key_jwt` is a credential the client must present, so such a client
            // is confidential: an authorization code alone does not redeem for it.
            'type' => $jwks !== null ? ClientType::Confidential : ClientType::Public,
            'token_endpoint_auth_method' => $jwks !== null ? TokenEndpointAuthMethod::PrivateKeyJwt : TokenEndpointAuthMethod::None,
            'redirect_uris' => $document->redirectUris,
            'grant_types' => $document->grantTypes,
            'scopes' => $scopes,
            'jwks' => $jwks,
            'first_party' => false,
            // Not columns: this model is never saved. Kept for the consent screen.
            'client_uri' => $document->clientUri,
            'logo_uri' => $document->logoUri,
        ]);

        return $client;
    }

    /** The document's `client_uri` (https only), or null. */
    public function clientUri(): ?string
    {
        $value = $this->getAttribute('client_uri');

        return is_string($value) ? $value : null;
    }

    /** The document's `logo_uri` (https only), or null. */
    public function logoUri(): ?string
    {
        $value = $this->getAttribute('logo_uri');

        return is_string($value) ? $value : null;
    }

    public function isDynamicallyRegistered(): bool
    {
        return true;
    }

    public function isMetadataDocumentClient(): bool
    {
        return true;
    }

    /**
     * The host that published the document — the one verified fact a consent screen can
     * show about this client.
     */
    public function documentHost(): string
    {
        return ClientIdUrl::host($this->client_id);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        throw new LogicException('A client described by a client ID metadata document is never persisted.');
    }

    public function delete(): ?bool
    {
        throw new LogicException('A client described by a client ID metadata document is never persisted.');
    }
}
