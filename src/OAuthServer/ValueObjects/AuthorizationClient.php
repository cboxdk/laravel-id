<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Contracts\AuthorizationClients;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\MetadataDocumentClient;

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
     * A metadata document client: EXACT string match against the document's
     * `redirect_uris`, loopback included — the document is the publisher's whole claim,
     * and there is no registration step at which a looser rule could have been agreed.
     * A registered client: exact match, or a loopback redirect differing only in port
     * (RFC 8252 §7.3, for native apps that bind an ephemeral port).
     */
    public function allowsRedirectUri(string $redirectUri): bool
    {
        $registered = array_values(array_filter($this->client->redirect_uris, 'is_string'));

        if (in_array($redirectUri, $registered, true)) {
            return true;
        }

        if ($this->isMetadataDocumentClient()) {
            return false;
        }

        $candidate = self::withoutLoopbackPort($redirectUri);

        if ($candidate === null) {
            return false;
        }

        foreach ($registered as $uri) {
            if (self::withoutLoopbackPort($uri) === $candidate) {
                return true;
            }
        }

        return false;
    }

    /**
     * An http loopback URI with its port removed, or null when it is not one.
     */
    private static function withoutLoopbackPort(string $uri): ?string
    {
        $parts = parse_url($uri);

        if (! is_array($parts) || ($parts['scheme'] ?? null) !== 'http'
            || ! in_array($parts['host'] ?? null, ['127.0.0.1', '[::1]', 'localhost'], true)) {
            return null;
        }

        return 'http://'.$parts['host'].($parts['path'] ?? '').(isset($parts['query']) ? '?'.$parts['query'] : '');
    }
}
