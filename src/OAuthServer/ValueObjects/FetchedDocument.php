<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;

/**
 * A JSON object fetched by a {@see MetadataDocumentFetcher}, with the freshness its server
 * declared. A serialization boundary: the body is the decoded wire document, parsed into
 * a typed value by whoever asked for it.
 */
readonly class FetchedDocument
{
    /**
     * @param  array<string, mixed>  $body
     */
    public function __construct(
        public array $body = [],
        /**
         * Seconds the server said the document may be reused (`Cache-Control: max-age`);
         * 0 for `no-store` / `no-cache`; null when it said nothing.
         */
        public ?int $maxAge = null,
    ) {}
}
