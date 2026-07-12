<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Delivers events over HTTP with an HMAC-SHA256 signature (secret opened from
 * the sealed store). Failures are recorded and retried with exponential backoff.
 */
final class HttpWebhookDispatcher implements WebhookDispatcher
{
    public function __construct(
        private readonly WebhookRegistry $registry,
        private readonly SecretBox $secretBox,
    ) {}

    public function dispatch(string $eventType, array $payload, ?string $organizationId = null): void
    {
        foreach ($this->registry->matching($organizationId, $eventType) as $endpoint) {
            $delivery = new WebhookDelivery;
            $delivery->fill([
                'endpoint_id' => $endpoint->id,
                'event_type' => $eventType,
                'payload' => $payload,
                'attempt' => 0,
                'status' => DeliveryStatus::Pending,
            ]);
            $delivery->save();

            $this->attempt($endpoint, $delivery);
        }
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
            'data' => $delivery->payload,
            'delivery_id' => $delivery->id,
        ], JSON_THROW_ON_ERROR);

        $delivery->attempt = $delivery->attempt + 1;

        // Re-check the URL immediately before sending (narrows DNS-rebinding) —
        // never deliver to a non-public address.
        if (! SafeWebhookUrl::isSafe($endpoint->url)) {
            $delivery->response_code = null;
            $this->scheduleRetry($delivery);
            $delivery->save();

            return;
        }

        $secret = $this->secretBox->open($endpoint->secret_encrypted, $endpoint->secretContext());
        $signature = hash_hmac('sha256', $body, $secret);

        try {
            $response = Http::withHeaders(['X-Cbox-Signature' => 'sha256='.$signature])
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
        $delivery->status = DeliveryStatus::Failed;
        $delivery->next_retry_at = now()->addMinutes(min(60, 2 ** $delivery->attempt));
    }
}
