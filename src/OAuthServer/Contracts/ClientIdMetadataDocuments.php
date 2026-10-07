<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\CachedClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\Models\MetadataDocumentClient;

/**
 * Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document): a client
 * whose `client_id` is an https URL, and whose metadata is the JSON document served there,
 * instead of a registration.
 *
 * It is how a client that has never seen this server — an MCP client meeting a new MCP
 * server — gets a client id without a registration endpoint: it already has one, and the
 * server reads the rest. Off unless `cbox-id.oauth.client_id_metadata_documents.enabled`.
 *
 * Bound to {@see CachedClientIdMetadataDocuments}. The token endpoint, PAR and revocation
 * consult it when a `client_id` is not a registered client, and the host's `/authorize`
 * reaches it through {@see AuthorizationClients}.
 */
interface ClientIdMetadataDocuments
{
    /**
     * Whether `$clientId` would be resolved here: the feature is on and the id has the
     * shape of a metadata document URL. No request is made to answer this.
     */
    public function supports(string $clientId): bool;

    /**
     * The client the document at `$clientId` describes, for the current environment —
     * fetched through the SSRF guard on a cache miss, validated, and narrowed to the
     * scopes a self-registered client may hold here.
     *
     * @throws InvalidClientMetadataDocument
     */
    public function resolve(string $clientId): MetadataDocumentClient;
}
