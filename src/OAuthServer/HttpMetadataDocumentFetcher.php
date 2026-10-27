<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\ValueObjects\FetchedDocument;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use GuzzleHttp\Exception\TransferException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use JsonException;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;

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
 *  - SIZE. The declared `Content-Length` is checked as the headers arrive, the transfer is
 *    stopped once more than the ceiling has arrived (a chunked body declares no length),
 *    and the body is measured again before it is parsed — a few kilobytes is all a
 *    client's metadata ever needs (`max_bytes`, 5120 by default). Through Guzzle's own
 *    `progress` option, never a raw curl option: Guzzle 8 refuses curl options outside its
 *    allow-list (CURLOPT_MAXFILESIZE among them) with an exception before sending.
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

        // The guard owns the `curl` options it returned (the DNS pin); nothing is added to
        // them. A body still arriving past the ceiling stops the transfer here.
        $options['progress'] = static function (mixed $downloadTotal, mixed $downloaded) use ($limit): void {
            if (is_int($downloaded) && $downloaded > $limit) {
                throw new RuntimeException('too_large');
            }
        };

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
        } catch (ConnectionException|RequestException|TransferException $e) {
            if ($this->stoppedForSize($e)) {
                throw InvalidClientMetadataDocument::tooLarge($limit);
            }

            throw InvalidClientMetadataDocument::fetchFailed($e->getMessage());
        } catch (RuntimeException $e) {
            // A callback's refusal can also surface unwrapped, straight out of the handler.
            if ($this->stoppedForSize($e)) {
                throw InvalidClientMetadataDocument::tooLarge($limit);
            }

            throw $e;
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

    /** The size callbacks' own refusal, however many layers Guzzle and Laravel wrapped it in. */
    private function stoppedForSize(Throwable $e): bool
    {
        for ($current = $e; $current !== null; $current = $current->getPrevious()) {
            if (str_contains($current->getMessage(), 'too_large')) {
                return true;
            }
        }

        return false;
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
