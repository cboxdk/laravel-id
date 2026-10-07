<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\HttpMetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Testing\FakeMetadataDocumentFetcher;
use Cbox\Id\OAuthServer\ValueObjects\FetchedDocument;

/**
 * Fetches a JSON document from a URL a CLIENT chose: a client ID metadata document, and
 * the `jwks_uri` it names.
 *
 * That makes it a server-side request to an attacker-chosen address, which is why it is a
 * contract of its own: the bound {@see HttpMetadataDocumentFetcher} goes through the SSRF
 * guard (resolved, pinned, no redirects), bounded in size and time, and a test swaps in
 * {@see FakeMetadataDocumentFetcher} rather than touching the network.
 */
interface MetadataDocumentFetcher
{
    /**
     * @throws InvalidClientMetadataDocument `unsafe_url`, `fetch_failed`, `too_large` or `invalid_json`
     */
    public function fetch(string $url): FetchedDocument;
}
