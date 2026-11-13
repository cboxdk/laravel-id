<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Contracts\AuthorizationClients;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\MetadataDocumentClient;
use Cbox\Id\OAuthServer\Support\WebRedirectUri;

/**
 * The client an authorization request names, as the host's `/authorize` and consent
 * screen need it ({@see AuthorizationClients}): the client, whether consent may ever be
 * skipped, and — for a client described by a metadata document — the facts a consent
 * screen should show instead of a registered name.
 */
readonly class AuthorizationClient
{
    public function __construct(
        public Client $client,
        /**
         * The host that published the client's metadata document, for a metadata
         * document client; null for a registered one. The ONE verified fact about such a
         * client — show it prominently ("client.example wants to…"), since the name is
         * whatever the publisher typed.
         */
        public ?string $documentHost = null,
        /** The document's `client_uri` (https only), for a "more about this app" link. */
        public ?string $clientUri = null,
        /** The document's `logo_uri` (https only). */
        public ?string $logoUri = null,
    ) {}

    public static function registered(Client $client): self
    {
        return new self($client);
    }

    public static function described(MetadataDocumentClient $client, ?string $clientUri = null, ?string $logoUri = null): self
    {
        return new self($client, $client->documentHost(), $clientUri, $logoUri);
    }

    public function isMetadataDocumentClient(): bool
    {
        return $this->client->isMetadataDocumentClient();
    }

    /**
     * Whether the person must be asked, whatever the host's own skip rules say. A client
     * that registered itself — RFC 7591 or a metadata document — is a stranger by
     * definition, so it never rides on a first-party exemption.
     */
    public function consentRequired(): bool
    {
        return $this->client->isDynamicallyRegistered();
    }

    /**
     * Whether `$redirectUri` is one this client may be sent back to.
     *
     * Exact string match against the client's `redirect_uris`, or a loopback redirect
     * differing only in port (RFC 8252 §7.3; OAuth 2.1 §8.4.2 makes the port exception a
     * MUST for the server). The same rule for a registered client and a metadata document
     * client: a native MCP client publishes `http://localhost/callback` in its document and
     * binds whatever port is free when it signs in, so an exact match on loopback would
     * refuse every such client after the first port.
     *
     * The port exception is reached only when both sides are loopback URIs in canonical
     * form ({@see WebRedirectUri::loopbackWithoutPort()}); anything else must match exactly.
     */
    public function allowsRedirectUri(string $redirectUri): bool
    {
        $registered = array_values(array_filter($this->client->redirect_uris, 'is_string'));

        if (in_array($redirectUri, $registered, true)) {
            return true;
        }

        $candidate = WebRedirectUri::loopbackWithoutPort($redirectUri);

        if ($candidate === null) {
            return false;
        }

        foreach ($registered as $uri) {
            if (WebRedirectUri::loopbackWithoutPort($uri) === $candidate) {
                return true;
            }
        }

        return false;
    }
}
