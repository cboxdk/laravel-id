<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use Cbox\Id\Webhooks\Jobs\DeliverWebhook;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\EndpointCircuitBreaker;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Delivers events over HTTP with an HMAC-SHA256 signature (secret opened from
 * the sealed store). Failures are recorded and retried with exponential backoff.
 *
 * Fan-out and SENDING are deliberately separated. {@see dispatch()} only writes
 * the delivery rows and queues a {@see DeliverWebhook} job for each; the blocking
 * `Http` call happens inside {@see deliver()}, on a worker. Doing the send inline
 * coupled every tenant's event throughput to the slowest receiver — see the job's
 * class docblock for the full account.
 */
class HttpWebhookDispatcher implements WebhookDispatcher
{
    public function __construct(
        private readonly WebhookRegistry $registry,
        private readonly SecretBox $secretBox,
        private readonly EndpointCircuitBreaker $breaker,
    ) {}

    public function dispatch(string $eventType, array $payload, ?string $organizationId = null): void
    {
        foreach ($this->registry->matching($organizationId, $eventType) as $endpoint) {
            $sequence = $this->nextSequence($endpoint);

            $delivery = new WebhookDelivery;
            $delivery->fill([
                'endpoint_id' => $endpoint->id,
                'event_type' => $eventType,
                'sequence' => $sequence,
                'payload' => $payload,
                'attempt' => 0,
                'status' => DeliveryStatus::Pending,
            ]);
            $delivery->save();

            // The row is durable BEFORE the job exists, so a queue that drops the
            // message still leaves the delivery visible to the retry sweep.
            $this->enqueue($delivery);
        }
    }

    /**
     * Allocate the next per-endpoint delivery sequence ATOMICALLY. A plain
     * `increment()` bumps the DB correctly but sets the in-memory attribute
     * optimistically (loaded + 1, no re-read), so two concurrent workers would stamp
     * the SAME number — defeating the gap-detection the sequence exists for. A
     * `lockForUpdate` read-modify-write serializes the workers so each gets a distinct,
     * gap-free value; the unique (endpoint_id, sequence) index is the backstop.
     */
    private function nextSequence(WebhookEndpoint $endpoint): int
    {
        return DB::transaction(function () use ($endpoint): int {
            $locked = WebhookEndpoint::query()->whereKey($endpoint->id)->lockForUpdate()->first();
            $next = ($locked ?? $endpoint)->last_sequence + 1;

            WebhookEndpoint::query()->whereKey($endpoint->id)->update(['last_sequence' => $next]);

            return $next;
        });
    }

    /**
     * Hand one delivery to the queue, honouring the host's connection/queue choice
     * so webhook egress can be isolated from the rest of the application's work.
     */
    private function enqueue(WebhookDelivery $delivery): void
    {
        $pending = DeliverWebhook::dispatch($delivery->id);

        $connection = config('cbox-id.webhooks.queue_connection');

        if (is_string($connection) && $connection !== '') {
            $pending->onConnection($connection);
        }

        $queue = config('cbox-id.webhooks.queue');

        if (is_string($queue) && $queue !== '') {
            $pending->onQueue($queue);
        }
    }

    public function retryPending(int $limit = 50): int
    {
        // Terminalise ORPHANS first — deliveries whose endpoint has been deleted — and do
        // it in the QUERY rather than by skipping them after selection.
        //
        // Deleting an endpoint does not cascade, and now that the send is asynchronous the
        // row outlives its job: deliver() finds no endpoint and returns, leaving the row
        // `Pending` forever. It is then re-selected by the stranded-rescue clause below on
        // every sweep, it consumed one of the `$limit` slots before being skipped, and —
        // because the sweep is ordered by `created_at` ASCENDING — orphans sit permanently
        // at the head of it. With `retry_limit` (50 by default) orphans, no legitimate
        // failed delivery was ever re-enqueued again, and the pruner could not remove them
        // either (it takes only Delivered/Exhausted). Exhausted is the honest status: the
        // endpoint is gone, so the delivery can never succeed.
        $this->terminaliseOrphans();

        $due = WebhookDelivery::query()
            // The endpoint must still exist. Stated as a predicate so an orphan never
            // occupies a slot in the first place — the previous `continue` inside the loop
            // ran AFTER the limit had already been spent on it.
            ->whereIn('endpoint_id', WebhookEndpoint::query()->select('id'))
            ->where(fn ($query) => $query
                // A recorded failure whose backoff window has elapsed.
                ->where(fn ($failed) => $failed
                    ->where('status', DeliveryStatus::Failed->value)
                    ->whereNotNull('next_retry_at')
                    ->where('next_retry_at', '<=', now()))
                // ...or a delivery that was recorded and queued but never processed:
                // the job was lost, the worker died, the queue was flushed. While the
                // send happened inline this state could not persist; now that the row
                // outlives its job, the sweep is what makes "durable before enqueued"
                // actually true. Same idea as the relay's own claim reclaim.
                ->orWhere(fn ($stranded) => $stranded
                    ->where('status', DeliveryStatus::Pending->value)
                    ->where('created_at', '<=', now()->subSeconds($this->strandedAfterSeconds()))))
            ->orderBy('created_at')
            ->limit($limit)
            ->get();

        $queued = 0;

        foreach ($due as $delivery) {
            $this->enqueue($delivery);
            $queued++;
        }

        return $queued;
    }

    /**
     * Settle every delivery whose endpoint no longer exists.
     *
     * A single set-based UPDATE: this runs on the per-minute sweep, and the population it
     * fixes is created in bulk (one endpoint deletion orphans every delivery it ever had).
     */
    private function terminaliseOrphans(): void
    {
        WebhookDelivery::query()
            ->whereIn('status', [DeliveryStatus::Pending->value, DeliveryStatus::Failed->value])
            ->whereNotIn('endpoint_id', WebhookEndpoint::query()->select('id'))
            ->update([
                'status' => DeliveryStatus::Exhausted->value,
                'next_retry_at' => null,
                'updated_at' => now(),
            ]);
    }

    public function deliver(string $deliveryId): void
    {
        $delivery = WebhookDelivery::query()->whereKey($deliveryId)->first();

        // Already settled — a duplicate job (or a replayed message) must not
        // re-send a delivered event or resurrect a dead-lettered one.
        if ($delivery === null
            || $delivery->status === DeliveryStatus::Delivered
            || $delivery->status === DeliveryStatus::Exhausted) {
            return;
        }

        $endpoint = WebhookEndpoint::query()->whereKey($delivery->endpoint_id)->first();

        // The endpoint was deleted between the row being written and the job running.
        // SETTLE the delivery rather than returning: returning left it `Pending` forever —
        // unsendable, unprunable, and re-selected by the stranded-delivery rescue on every
        // sweep from then on. Endpoint deletion does not cascade, so this is the only
        // place the row can learn its fate.
        if ($endpoint === null) {
            $delivery->status = DeliveryStatus::Exhausted;
            $delivery->next_retry_at = null;
            $delivery->save();

            return;
        }

        $this->attempt($endpoint, $delivery);
    }

    private function attempt(WebhookEndpoint $endpoint, WebhookDelivery $delivery): void
    {
        // Circuit breaker: an endpoint that has just tripped is left alone until its
        // cooldown elapses. The delivery keeps its attempt count — the trip is the
        // endpoint's fault, not this delivery's — and simply waits, so a blackholing
        // receiver costs ONE timeout per cooldown window instead of one per event.
        if (! $this->breaker->shouldAttempt($endpoint)) {
            $delivery->status = DeliveryStatus::Failed;
            $delivery->next_retry_at = $this->breaker->closesAt($endpoint);
            $delivery->save();

            return;
        }

        $body = json_encode([
            'type' => $delivery->event_type,
            'sequence' => $delivery->sequence,
            'data' => $delivery->payload,
            'delivery_id' => $delivery->id,
        ], JSON_THROW_ON_ERROR);

        $delivery->attempt = $delivery->attempt + 1;

        // Validate the URL and pin the connection to the exact IPs just resolved,
        // immediately before sending — so a DNS rebind between check and connect
        // can't redirect the delivery to an internal address (TOCTOU-closed).
        try {
            $pinned = SafeWebhookUrl::pinnedOptions($endpoint->url);
        } catch (UnsafeWebhookUrl) {
            // A refused URL is OUR policy decision about a misconfiguration, not
            // evidence the receiver is unhealthy — it must not trip the breaker
            // (the same line provisioning draws between permanent and transient).
            $delivery->response_code = null;
            $this->scheduleRetry($delivery);
            $delivery->save();

            return;
        }

        $secret = $this->secretBox->open($endpoint->secret_encrypted, $endpoint->secretContext());

        // Sign `timestamp.body` (Stripe-style) so a receiver can bind the signature
        // to a moment and reject a replayed delivery outside its tolerance window.
        $timestamp = time();
        $signature = hash_hmac('sha256', $timestamp.'.'.$body, $secret);

        try {
            $response = Http::withHeaders([
                'X-Cbox-Timestamp' => (string) $timestamp,
                'X-Cbox-Signature' => 't='.$timestamp.',v1='.$signature,
            ])
                ->withOptions($pinned)          // pinned resolution + no redirects
                ->withoutRedirecting()          // a 30x to an internal host must not be followed
                ->connectTimeout(5)
                ->timeout(10)
                ->withBody($body, 'application/json')
                ->post($endpoint->url);

            $delivery->response_code = $response->status();

            if ($response->successful()) {
                $delivery->status = DeliveryStatus::Delivered;
                $delivery->delivered_at = now();
                $delivery->next_retry_at = null;
                $this->breaker->recordSuccess($endpoint);
            } else {
                $this->scheduleRetry($delivery);
                $this->breaker->recordFailure($endpoint, 'HTTP '.$response->status());
            }
        } catch (Throwable $e) {
            $delivery->response_code = null;
            $this->scheduleRetry($delivery);
            $this->breaker->recordFailure($endpoint, $e->getMessage());
        }

        $delivery->save();
        $endpoint->save();
    }

    /** How long a still-Pending delivery may sit before the sweep re-enqueues it. */
    private function strandedAfterSeconds(): int
    {
        $configured = config('cbox-id.webhooks.stranded_after_seconds', 900);

        return max(1, is_numeric($configured) ? (int) $configured : 900);
    }

    private function scheduleRetry(WebhookDelivery $delivery): void
    {
        // Bound the retries: once the cap is hit, dead-letter the delivery so it
        // stops consuming retry cycles forever (an endpoint that's gone stays gone).
        $configured = config('cbox-id.webhooks.max_attempts', 12);
        $maxAttempts = is_numeric($configured) ? (int) $configured : 12;

        if ($delivery->attempt >= $maxAttempts) {
            $delivery->status = DeliveryStatus::Exhausted;
            $delivery->next_retry_at = null;

            return;
        }

        $delivery->status = DeliveryStatus::Failed;
        $delivery->next_retry_at = now()->addMinutes(min(60, 2 ** $delivery->attempt));
    }
}
