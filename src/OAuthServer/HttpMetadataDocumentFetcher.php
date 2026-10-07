<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\ValueObjects\FetchedDocument;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use JsonException;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * The default {@see MetadataDocumentFetcher}: an https GET through `cboxdk/laravel-ssrf`.
 *
 * THE URL IS THE ATTACKER'S. Anyone can put any https URL in `client_id`, so this request
 * is aimed by whoever loads `/authorize`. Each limit is there for that:
 *
 *  - SSRF GUARD, PINNED. The host is resolved once, every address checked public, and the
 *    connection pinned to exactly those addresses — a DNS answer that changes between the
 *    check and the connect cannot steer the request inward. https only, no credentials.
 *  - NO REDIRECTS, ever — even with host verification switched off for development. A
 *    document URL that 302s to the metadata service would otherwise be followed.
 *  - SIZE. The declared `Content-Length` is checked as the headers arrive, curl is told the
 *    ceiling, and the body is measured again before it is parsed — a few kilobytes is all
 *    a client's metadata ever needs (`max_bytes`, 5120 by default).
 *  - TIME. A short connect and total timeout, so a slow host stalls one request briefly
 *    rather than holding a worker.
 *
 * `Cache-Control: max-age` / `no-store` / `no-cache` is reported back; the caller decides
 * how long to keep the document.
 */
class HttpMetadataDocumentFetcher implements MetadataDocumentFetcher
{
    private const CONFIG = 'cbox-id.oauth.client_id_metadata_documents';

    public function fetch(string $url): FetchedDocument
    {
        $limit = $this->integer('max_bytes', 5120);

        $options = $this->pinned($url);

        // The guard owns the `curl` options it returned (the DNS pin); the size ceiling is
        // added beside them, never instead of them.
        // (Guarded like the SSRF package guards CURLOPT_RESOLVE: the curl extension is not a
        // hard requirement, and without it the header check and the final measure remain.)
        if (defined('CURLOPT_MAXFILESIZE')) {
            $curl = isset($options['curl']) && is_array($options['curl']) ? $options['curl'] : [];
            $curl[constant('CURLOPT_MAXFILESIZE')] = $limit;
            $options['curl'] = $curl;
        }

        $options['on_headers'] = static function (ResponseInterface $response) use ($limit): void {
            $length = $response->getHeaderLine('Content-Length');

            if (is_numeric($length) && (int) $length > $limit) {
                throw new RuntimeException('too_large');
            }
        };

        try {
            $response = Http::withOptions($options)
                ->connectTimeout($this->integer('connect_timeout', 3))
                ->timeout($this->integer('timeout', 5))
                ->accept('application/json')
                ->get($url);
        } catch (ConnectionException|RequestException $e) {
            if (str_contains($e->getMessage(), 'too_large') || str_contains($e->getMessage(), 'Maximum file size')) {
                throw InvalidClientMetadataDocument::tooLarge($limit);
            }

            throw InvalidClientMetadataDocument::fetchFailed($e->getMessage());
        }

        if ($response->status() !== 200) {
            throw InvalidClientMetadataDocument::fetchFailed("HTTP {$response->status()}");
        }

        $body = $response->body();

        if (strlen($body) > $limit) {
            throw InvalidClientMetadataDocument::tooLarge($limit);
        }

        return new FetchedDocument($this->decode($body), $this->maxAge($response));
    }

    /**
     * Guzzle options that pin the connection to the addresses the guard approved.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidClientMetadataDocument
     */
    private function pinned(string $url): array
    {
        if (! UrlVerification::enforced(self::CONFIG.'.verify_url')) {
            // Redirects stay refused with host verification off: the toggle exists to
            // reach a development host, never to follow a 302 to wherever it points.
            return ['allow_redirects' => false];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url, ['https']);
        } catch (BlockedUrl $e) {
            throw InvalidClientMetadataDocument::unsafeUrl($e->getMessage());
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidClientMetadataDocument
     */
    private function decode(string $body): array
    {
        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw InvalidClientMetadataDocument::notJson();
        }

        // An OBJECT: a JSON array decodes to a list, which is not a document.
        if (! is_array($decoded) || array_is_list($decoded)) {
            throw InvalidClientMetadataDocument::notJson();
        }

        $document = [];

        foreach ($decoded as $key => $value) {
            $document[(string) $key] = $value;
        }

        return $document;
    }

    /**
     * What the server said about reuse: `max-age` seconds, 0 for `no-store` / `no-cache`,
     * null for nothing. `s-maxage` is for shared caches, which this is not.
     */
    private function maxAge(Response $response): ?int
    {
        $header = strtolower($response->header('Cache-Control'));

        if ($header === '') {
            return null;
        }

        if (str_contains($header, 'no-store') || str_contains($header, 'no-cache')) {
            return 0;
        }

        if (preg_match('/(?:^|[,\s])max-age\s*=\s*"?(\d+)"?/', $header, $matches) === 1) {
            return (int) $matches[1];
        }

        return null;
    }

    private function integer(string $key, int $default): int
    {
        $value = config(self::CONFIG.'.'.$key, $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}
