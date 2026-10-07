<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\Contracts\ClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\Models\MetadataDocumentClient;
use Cbox\Id\OAuthServer\Support\ClientIdUrl;
use Cbox\Id\OAuthServer\Support\SelfRegisteredScopes;
use Cbox\Id\OAuthServer\ValueObjects\ClientMetadataDocument;
use Cbox\Id\OAuthServer\ValueObjects\FetchedDocument;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * The default {@see ClientIdMetadataDocuments}: fetch, validate, cache, describe.
 *
 * CACHED FOR AS LONG AS THE PUBLISHER SAYS, WITHIN BOUNDS. One sign-in reads the document
 * at `/authorize`, again at consent, and again at the token endpoint; fetching it three
 * times is three requests to somebody else's server for one person's click. So the
 * validated document is cached under its URL for its `Cache-Control: max-age`, held
 * between `min_ttl` (so `no-store` still survives one sign-in) and `max_ttl` (so a
 * publisher's edit — a removed redirect URI — takes effect within a day at worst), and for
 * `default_ttl` when the publisher said nothing.
 *
 * WHAT IS CACHED IS RE-VALIDATED. The cache holds the validated document as data, and it
 * goes back through {@see ClientMetadataDocument::fromArray()} on the way out — a cache
 * entry is never more trusted than the wire.
 *
 * The cached document is environment-neutral (the publisher wrote one document); the
 * CLIENT built from it is not — its scopes are what this environment lets a
 * self-registered client hold — so it is built fresh per call.
 */
class CachedClientIdMetadataDocuments implements ClientIdMetadataDocuments
{
    use ResolvesEnvironment;

    private const CONFIG = 'cbox-id.oauth.client_id_metadata_documents';

    private const CACHE_PREFIX = 'cbox-id:cimd:';

    public function __construct(
        private readonly MetadataDocumentFetcher $fetcher,
        private readonly SelfRegisteredScopes $scopes,
        private readonly Cache $cache,
    ) {}

    public function supports(string $clientId): bool
    {
        return $this->enabled() && ClientIdUrl::isValid($clientId);
    }

    public function resolve(string $clientId): MetadataDocumentClient
    {
        if (! $this->enabled()) {
            throw InvalidClientMetadataDocument::disabled();
        }

        if (! ClientIdUrl::isValid($clientId)) {
            throw InvalidClientMetadataDocument::invalidClientId($clientId);
        }

        $environment = $this->environments()->current();

        // A client is always some environment's client; with none in context there is no
        // issuer it could be authorized at, so there is nothing to describe.
        if ($environment === null) {
            throw InvalidClientMetadataDocument::disabled();
        }

        $document = $this->document($clientId);

        return MetadataDocumentClient::describe(
            $document,
            $environment->environmentKey(),
            $this->scopes->narrow($document->scopes, $document->refreshes()),
            $document->jwksUri !== null ? $this->keySet($document->jwksUri) : null,
        );
    }

    /**
     * @throws InvalidClientMetadataDocument
     */
    private function document(string $url): ClientMetadataDocument
    {
        $key = self::CACHE_PREFIX.'doc:'.hash('sha256', $url);
        $cached = $this->cache->get($key);

        if (is_array($cached)) {
            return ClientMetadataDocument::fromArray($this->stringKeyed($cached), $url);
        }

        $fetched = $this->fetcher->fetch($url);
        $document = ClientMetadataDocument::fromArray($fetched->body, $url);

        $this->cache->put($key, $document->toArray(), $this->ttl($fetched));

        return $document;
    }

    /**
     * The JWK Set a `private_key_jwt` document points at, cached on the same terms.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidClientMetadataDocument
     */
    private function keySet(string $url): array
    {
        $key = self::CACHE_PREFIX.'jwks:'.hash('sha256', $url);
        $cached = $this->cache->get($key);

        if (is_array($cached)) {
            return $this->validKeySet($this->stringKeyed($cached));
        }

        $fetched = $this->fetcher->fetch($url);
        $keys = $this->validKeySet($fetched->body);

        $this->cache->put($key, $keys, $this->ttl($fetched));

        return $keys;
    }

    /**
     * @param  array<string, mixed>  $keySet
     * @return array<string, mixed>
     *
     * @throws InvalidClientMetadataDocument
     */
    private function validKeySet(array $keySet): array
    {
        $keys = $keySet['keys'] ?? null;

        if (! is_array($keys) || $keys === [] || ! array_is_list($keys)) {
            throw InvalidClientMetadataDocument::field('jwks_uri', 'must serve a JWK Set with at least one key');
        }

        return ['keys' => $keys];
    }

    /**
     * Seconds to keep a fetched document: the publisher's `max-age`, held between the
     * configured bounds, or the default when the publisher said nothing.
     */
    private function ttl(FetchedDocument $fetched): int
    {
        $min = $this->seconds('min_ttl', 60);
        $max = max($min, $this->seconds('max_ttl', 86400));

        $declared = $fetched->maxAge ?? $this->seconds('default_ttl', 3600);

        return max($min, min($max, $declared));
    }

    private function enabled(): bool
    {
        return filter_var(config(self::CONFIG.'.enabled', false), FILTER_VALIDATE_BOOL);
    }

    private function seconds(string $key, int $default): int
    {
        $value = config(self::CONFIG.'.'.$key, $default);

        return is_numeric($value) && (int) $value >= 0 ? (int) $value : $default;
    }

    /**
     * @param  array<array-key, mixed>  $value
     * @return array<string, mixed>
     */
    private function stringKeyed(array $value): array
    {
        $keyed = [];

        foreach ($value as $key => $item) {
            $keyed[(string) $key] = $item;
        }

        return $keyed;
    }
}
