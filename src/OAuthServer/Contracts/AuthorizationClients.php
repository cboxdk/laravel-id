<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\DefaultAuthorizationClients;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizationClient;

/**
 * Which client an authorization request is from — the first question the host's
 * `/authorize` asks, answered in one place for every kind of client.
 *
 * A registered client (operator-created, or RFC 7591) is looked up; a `client_id` that is
 * an https URL, when client ID metadata documents are enabled, is resolved from its
 * document. The host renders `null` as "unknown client" and an
 * {@see InvalidClientMetadataDocument} as an error page — never a redirect, because
 * neither has a verified redirect URI to send the error to (RFC 6749 §4.1.2.1).
 *
 * Bound to {@see DefaultAuthorizationClients}.
 */
interface AuthorizationClients
{
    /**
     * @throws InvalidClientMetadataDocument when `$clientId` is a document URL whose document cannot be used
     */
    public function resolve(string $clientId): ?AuthorizationClient;
}
