<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Delivers events over HTTP with an HMAC-SHA256 signature (secret opened from
 * the sealed store). Failures are recorded and retried with exponential backoff.
 */
class HttpWebhookDispatcher implements WebhookDispatcher
{
    public function __construct(
        private readonly WebhookRegistry $registry,
        private readonly SecretBox $secretBox,
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

            $this->attempt($endpoint, $delivery);
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

    public function retryPending(int $limit = 50): int
    {
        $due = WebhookDelivery::query()
            ->where('status', DeliveryStatus::Failed->value)
            ->whereNotNull('next_retry_at')
            ->where('next_retry_at', '<=', now())
            ->limit($limit)
            ->get();

        foreach ($due as $delivery) {
            $endpoint = WebhookEndpoint::query()->whereKey($delivery->endpoint_id)->first();

            if ($endpoint === null) {
                continue;
            }

            $this->attempt($endpoint, $delivery);
        }

        return $due->count();
    }

    private function attempt(WebhookEndpoint $endpoint, WebhookDelivery $delivery): void
    {
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
            } else {
                $this->scheduleRetry($delivery);
            }
        } catch (Throwable) {
            $delivery->response_code = null;
            $this->scheduleRetry($delivery);
        }

        $delivery->save();
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
