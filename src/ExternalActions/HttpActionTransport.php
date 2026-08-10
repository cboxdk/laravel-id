<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\ConcurrentActionTransport;
use Cbox\Id\ExternalActions\Enums\ActionVerdict;
use Cbox\Id\ExternalActions\Enums\FailPolicy;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use Cbox\Id\ExternalActions\ValueObjects\PreparedActionRequest;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Ssrf\Contracts\UrlGuard;
use Illuminate\Http\Client\Pool;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * The default synchronous transport for external hook endpoints. It POSTs a signed,
 * SSRF-pinned, short-timeout request (no redirects, no retry, TLS verify left ON).
 * Any transport error, non-2xx, unsafe/rebinding target, or unparseable body means
 * the endpoint was not consulted, and what THAT means is the hook point's
 * {@see FailPolicy} — a deny at a gate (the default at every point that guards a
 * write), a skip where locking users out would be the worse failure. This is the
 * security-critical egress; it mirrors the webhook dispatcher's hardening, only
 * synchronous.
 *
 * The request body is `{"context": {...}}`; the reply is interpreted as
 * `{"action":"continue"|"deny", "claims":{...}, "reason":"..."}`. The request is
 * signed HMAC-SHA256 over `"{timestamp}.{body}"` with `X-Cbox-Signature: t=..,v1=..`,
 * the same scheme (and same receiver verification) as webhooks.
 */
class HttpActionTransport implements ConcurrentActionTransport
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
            $prepared = $this->prepare($endpoint, $context);

            $response = Http::withHeaders($prepared->headers)
                ->withOptions($prepared->options)   // pinned resolution + no redirects (TOCTOU)
                ->withoutRedirecting()              // a 30x to an internal host must not be followed
                ->connectTimeout($this->connectTimeout())
                ->timeout($this->timeout())
                ->withBody($prepared->body, 'application/json')
                ->post($prepared->url);
        } catch (Throwable) {
            return $this->onFailure($context);
        }

        if (! $response->successful()) {
            return $this->onFailure($context);
        }

        return $this->interpret($response->json(), $context);
    }

    /**
     * Fire the whole fan-out at once.
     *
     * Sequentially, N hooks cost N × (connect timeout + read timeout) on the token
     * path. Pooled, they cost ONE endpoint's budget however many there are — which is
     * the total pipeline budget this module previously had no way to state.
     *
     * Every guarantee of the single send is preserved per request: the same signature,
     * the same pinned resolution, the same refusal to follow redirects, the same
     * fail-closed reading of the reply. A preparation that throws (an SSRF rejection,
     * an unopenable secret) becomes that endpoint's deny alone and does not disturb
     * the others.
     *
     * @param  Collection<int, ExternalActionEndpoint>  $endpoints
     * @return array<string, ActionResult>
     */
    public function sendMany(Collection $endpoints, ActionContext $context): array
    {
        /** @var array<string, PreparedActionRequest> $prepared */
        $prepared = [];
        /** @var array<string, ActionResult> $results */
        $results = [];

        foreach ($endpoints as $endpoint) {
            try {
                $prepared[$endpoint->id] = $this->prepare($endpoint, $context);
            } catch (Throwable) {
                $results[$endpoint->id] = $this->onFailure($context);
            }
        }

        if ($prepared === []) {
            return $results;
        }

        $connectTimeout = $this->connectTimeout();
        $timeout = $this->timeout();

        /** @var array<string, mixed> $responses */
        $responses = Http::pool(static function (Pool $pool) use ($prepared, $connectTimeout, $timeout): array {
            $requests = [];

            foreach ($prepared as $id => $request) {
                $requests[] = $pool->as($id)
                    ->withHeaders($request->headers)
                    ->withOptions($request->options)
                    ->withoutRedirecting()
                    ->connectTimeout($connectTimeout)
                    ->timeout($timeout)
                    ->withBody($request->body, 'application/json')
                    ->post($request->url);
            }

            return $requests;
        });

        foreach ($prepared as $id => $request) {
            // A pooled request surfaces its transport failure as the exception object
            // in the result array rather than throwing — anything that is not a
            // successful Response is a fail-closed deny, exactly as in send().
            $response = $responses[$id] ?? null;

            $results[$id] = $response instanceof Response && $response->successful()
                ? $this->interpret($response->json(), $context)
                : $this->onFailure($context);
        }

        return $results;
    }

    /**
     * Assemble one signed, SSRF-pinned request. Shared by the single and pooled paths
     * so neither can drift from the other's hardening.
     */
    private function prepare(ExternalActionEndpoint $endpoint, ActionContext $context): PreparedActionRequest
    {
        $pinned = config('cbox-id.external_actions.verify_url', true) === true
            ? $this->ssrf->pinnedOptions($endpoint->url)
            : [];

        $body = json_encode(['context' => $context->toArray()], JSON_THROW_ON_ERROR);
        $secret = $this->secretBox->open($endpoint->secret_encrypted, $endpoint->secretContext());
        $timestamp = time();
        $signature = hash_hmac('sha256', $timestamp.'.'.$body, $secret);

        return new PreparedActionRequest(
            endpointId: $endpoint->id,
            url: $endpoint->url,
            body: $body,
            headers: [
                'X-Cbox-Timestamp' => (string) $timestamp,
                'X-Cbox-Signature' => 't='.$timestamp.',v1='.$signature,
            ],
            options: $pinned,
        );
    }

    private function interpret(mixed $json, ActionContext $context): ActionResult
    {
        if (! is_array($json)) {
            return $this->onFailure($context);
        }

        // AN UNRECOGNISED VERB IS AN UNANSWERED GATE, so it goes to the hook point's fail
        // policy rather than being read as permission. `($json['action'] ?? 'continue')
        // === 'deny'` continued on an absent action, a misspelling, and on `DENY` — which
        // silently disabled a customer's FailClosed gate while returning 2xx, so nothing
        // anywhere recorded a failure. See ActionVerdict.
        $verdict = ActionVerdict::parse($json['action'] ?? null);

        if ($verdict === null) {
            return $this->onFailure($context);
        }

        if ($verdict === ActionVerdict::Deny) {
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
     * An endpoint that could not be CONSULTED — refused, timed out, answered non-2xx,
     * or replied with something that is not a hook reply.
     *
     * What that means is the hook point's decision, not the transport's: a gate fails
     * closed (a security control that fails open is not a control) while the login
     * hook fails open, because a customer's endpoint going down must not lock their
     * whole tenant out. See {@see FailPolicy} for the precedence, and
     * {@see HookPoint::failPolicy()} for each
     * default and why it is what it is.
     */
    private function onFailure(ActionContext $context): ActionResult
    {
        return FailPolicy::for($context->hookPoint)->isOpen()
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
