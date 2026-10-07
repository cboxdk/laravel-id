<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Testing;

use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\ValueObjects\FetchedDocument;

/**
 * An in-memory web for client ID metadata documents: serve a document (or a key set) at
 * a URL, or make a URL fail the way the real fetcher would — `unsafe_url` for an address
 * the SSRF guard refuses, `fetch_failed`, `too_large`, `invalid_json`.
 *
 * A URL that was never served fails as `fetch_failed`, like a 404. Every URL asked for is
 * recorded in {@see $fetched}, so a test can assert the cache spared the second request.
 */
class FakeMetadataDocumentFetcher implements MetadataDocumentFetcher
{
    /** @var list<string> every URL asked for, in order */
    public array $fetched = [];

    /** @var array<string, FetchedDocument> */
    private array $documents = [];

    /** @var array<string, InvalidClientMetadataDocument> */
    private array $failures = [];

    /**
     * @param  array<string, mixed>  $document
     */
    public function serve(string $url, array $document, ?int $maxAge = null): self
    {
        $this->documents[$url] = new FetchedDocument($document, $maxAge);
        unset($this->failures[$url]);

        return $this;
    }

    public function fail(string $url, InvalidClientMetadataDocument $failure): self
    {
        $this->failures[$url] = $failure;
        unset($this->documents[$url]);

        return $this;
    }

    /**
     * Refuse `$url` the way the SSRF guard refuses a private, loopback or metadata address.
     */
    public function refuseAsUnsafe(string $url): self
    {
        return $this->fail($url, InvalidClientMetadataDocument::unsafeUrl('resolves to a non-public address'));
    }

    public function fetch(string $url): FetchedDocument
    {
        $this->fetched[] = $url;

        if (isset($this->failures[$url])) {
            throw $this->failures[$url];
        }

        return $this->documents[$url] ?? throw InvalidClientMetadataDocument::fetchFailed('HTTP 404');
    }
}
