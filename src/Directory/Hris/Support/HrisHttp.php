<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\Support;

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Closure;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Sleep;

/**
 * One request to an HR system's API, retried the way a rate-limited API asks to be.
 *
 * HR APIs are small and strict: BambooHR, HiBob, Personio and Rippling all answer `429`
 * under load, some with `Retry-After`, some with a reset timestamp, some with nothing. A
 * full pull of a few thousand employees crosses those limits as a matter of course, and a
 * sync that gives up on the first `429` deprovisions nobody and provisions half the company.
 *
 * So `429` and the transient `502`/`503`/`504` are retried — honouring `Retry-After`
 * (seconds or an HTTP date) or `X-RateLimit-Reset` / `RateLimit-Reset` when the server
 * sends one, exponential otherwise — up to `cbox-id.directory.hris.max_attempts`, never
 * waiting longer than `cbox-id.directory.hris.max_backoff_seconds` at a time. Any other
 * failure is final at once: a `401` does not become a `200` by asking again.
 *
 * The waiting goes through {@see Sleep}, so a test fakes the clock rather than the sync
 * taking a minute.
 *
 * Messages carry the status and what was being fetched, never a URL with a query string
 * and never a header: either could hold a credential.
 */
final class HrisHttp
{
    private const array TRANSIENT = [429, 502, 503, 504];

    private readonly int $maxAttempts;

    private readonly int $maxBackoff;

    public function __construct(private readonly string $provider, ?int $maxAttempts = null, ?int $maxBackoffSeconds = null)
    {
        $attempts = $maxAttempts ?? config('cbox-id.directory.hris.max_attempts', 5);
        $backoff = $maxBackoffSeconds ?? config('cbox-id.directory.hris.max_backoff_seconds', 60);

        $this->maxAttempts = max(1, is_numeric($attempts) ? (int) $attempts : 5);
        $this->maxBackoff = max(0, is_numeric($backoff) ? (int) $backoff : 60);
    }

    /**
     * Send, retrying transient refusals, and return the successful response.
     *
     * @param  Closure(): Response  $send
     *
     * @throws DirectoryConnectionFailed
     */
    public function send(Closure $send, string $what): Response
    {
        $attempt = 0;

        while (true) {
            $attempt++;

            try {
                $response = $send();
            } catch (ConnectionException) {
                if ($attempt >= $this->maxAttempts) {
                    throw DirectoryConnectionFailed::make($this->provider, "{$what}: could not connect after {$attempt} attempts.");
                }

                Sleep::for($this->exponential($attempt))->seconds();

                continue;
            }

            $status = $response->status();

            if (in_array($status, self::TRANSIENT, true)) {
                if ($attempt >= $this->maxAttempts) {
                    $why = $status === 429 ? 'rate limited' : 'unavailable';

                    throw DirectoryConnectionFailed::make($this->provider, "{$what} was {$why} ({$status}) after {$attempt} attempts.");
                }

                Sleep::for($this->delay($response, $attempt))->seconds();

                continue;
            }

            if (! $response->successful()) {
                throw DirectoryConnectionFailed::make($this->provider, "{$what} failed ({$status}){$this->hint($status)}.");
            }

            return $response;
        }
    }

    /** How long to wait before the next attempt, in whole seconds. */
    public function delay(Response $response, int $attempt): int
    {
        $retryAfter = trim($response->header('Retry-After'));

        if ($retryAfter !== '') {
            if (ctype_digit($retryAfter)) {
                return $this->cap((int) $retryAfter);
            }

            try {
                return $this->cap((int) ceil(CarbonImmutable::now()->diffInSeconds(CarbonImmutable::parse($retryAfter), false)));
            } catch (\Throwable) {
                // An unreadable date is no date: fall through to the reset headers.
            }
        }

        foreach (['X-RateLimit-Reset', 'RateLimit-Reset', 'X-Rate-Limit-Reset'] as $header) {
            $reset = trim($response->header($header));

            if ($reset !== '' && ctype_digit($reset)) {
                $value = (int) $reset;

                // An epoch timestamp, or a number of seconds from now (RFC draft RateLimit).
                $seconds = $value > 1_000_000_000 ? $value - CarbonImmutable::now()->getTimestamp() : $value;

                return $this->cap($seconds);
            }
        }

        return $this->exponential($attempt);
    }

    private function exponential(int $attempt): int
    {
        return $this->cap(2 ** min($attempt, 10));
    }

    private function cap(int $seconds): int
    {
        return max(1, min($seconds, $this->maxBackoff));
    }

    private function hint(int $status): string
    {
        return match ($status) {
            401 => ': the credentials were refused',
            403 => ': the credentials lack permission to read employees',
            404 => ': not found — check the account, subdomain or report address',
            default => '',
        };
    }
}
