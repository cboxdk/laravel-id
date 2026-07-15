<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Ssrf\Contracts\UrlGuard;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * The default synchronous transport for external hook endpoints. It POSTs a signed,
 * SSRF-pinned, short-timeout request (no redirects, no retry, TLS verify left ON) and
 * FAILS CLOSED — any transport error, non-2xx, unsafe/rebinding target, or
 * unparseable body becomes a deny (unless `external_actions.fail_open` is set). This
 * is the security-critical egress; it mirrors the webhook dispatcher's hardening,
 * only synchronous.
 *
 * The request body is `{"context": {...}}`; the reply is interpreted as
 * `{"action":"continue"|"deny", "claims":{...}, "reason":"..."}`. The request is
 * signed HMAC-SHA256 over `"{timestamp}.{body}"` with `X-Cbox-Signature: t=..,v1=..`,
 * the same scheme (and same receiver verification) as webhooks.
 */
final class HttpActionTransport implements ActionTransport
{
    private const DEFAULT_TIMEOUT = 3;

    private const DEFAULT_CONNECT_TIMEOUT = 2;

    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly UrlGuard $ssrf,
    ) {}

    public function send(ExternalActionEndpoint $endpoint, ActionContext $context): ActionResult
    {
        try {
            $pinned = config('cbox-id.external_actions.verify_url', true) === true
                ? $this->ssrf->pinnedOptions($endpoint->url)
                : [];

            $body = json_encode(['context' => $context->toArray()], JSON_THROW_ON_ERROR);
            $secret = $this->secretBox->open($endpoint->secret_encrypted, $endpoint->secretContext());
            $timestamp = time();
            $signature = hash_hmac('sha256', $timestamp.'.'.$body, $secret);

            $response = Http::withHeaders([
                'X-Cbox-Timestamp' => (string) $timestamp,
                'X-Cbox-Signature' => 't='.$timestamp.',v1='.$signature,
            ])
                ->withOptions($pinned)          // pinned resolution + no redirects (TOCTOU)
                ->withoutRedirecting()          // a 30x to an internal host must not be followed
                ->connectTimeout($this->connectTimeout())
                ->timeout($this->timeout())
                ->withBody($body, 'application/json')
                ->post($endpoint->url);
        } catch (Throwable) {
            return $this->onFailure();
        }

        if (! $response->successful()) {
            return $this->onFailure();
        }

        return $this->interpret($response->json());
    }

    private function interpret(mixed $json): ActionResult
    {
        if (! is_array($json)) {
            return $this->onFailure();
        }

        if (($json['action'] ?? 'continue') === 'deny') {
            $reason = is_string($json['reason'] ?? null) ? $json['reason'] : 'denied by external action';

            return ActionResult::deny($reason);
        }

        // Only string-keyed entries are usable as claim enrichment.
        $claims = $json['claims'] ?? [];
        $enrichment = [];

        if (is_array($claims)) {
            foreach ($claims as $key => $value) {
                if (is_string($key)) {
                    $enrichment[$key] = $value;
                }
            }
        }

        return ActionResult::continue($enrichment);
    }

    /**
     * Fail-closed by default: an unreachable or misbehaving hook denies the operation
     * (a security control that fails open is not a control). Set `fail_open` to trade
     * that for availability on enrichment-only hooks.
     */
    private function onFailure(): ActionResult
    {
        return config('cbox-id.external_actions.fail_open', false) === true
            ? ActionResult::continue()
            : ActionResult::deny('external action unavailable');
    }

    private function timeout(): int
    {
        $value = config('cbox-id.external_actions.timeout', self::DEFAULT_TIMEOUT);

        return is_numeric($value) ? max(1, (int) $value) : self::DEFAULT_TIMEOUT;
    }

    private function connectTimeout(): int
    {
        $value = config('cbox-id.external_actions.connect_timeout', self::DEFAULT_CONNECT_TIMEOUT);

        return is_numeric($value) ? max(1, (int) $value) : self::DEFAULT_CONNECT_TIMEOUT;
    }
}
