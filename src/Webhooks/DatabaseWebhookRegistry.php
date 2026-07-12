<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

final class DatabaseWebhookRegistry implements WebhookRegistry
{
    public function __construct(private readonly SecretBox $secretBox) {}

    public function register(?string $organizationId, string $url, array $eventTypes): RegisteredEndpoint
    {
        $secret = bin2hex(random_bytes(32));

        $endpoint = new WebhookEndpoint;
        $endpoint->id = (string) Str::ulid();
        $endpoint->fill([
            'organization_id' => $organizationId,
            'url' => $url,
            'event_types' => $eventTypes,
            'status' => EndpointStatus::Active,
        ]);
        $endpoint->secret_encrypted = $this->secretBox->seal($secret, $endpoint->secretContext());
        $endpoint->save();

        return new RegisteredEndpoint($endpoint, $secret);
    }

    public function pause(string $endpointId): void
    {
        $endpoint = WebhookEndpoint::query()->whereKey($endpointId)->first();

        $endpoint?->update(['status' => EndpointStatus::Paused]);
    }

    public function matching(?string $organizationId, string $eventType): Collection
    {
        return WebhookEndpoint::query()
            ->where('status', EndpointStatus::Active->value)
            ->where(function ($query) use ($organizationId): void {
                $query->whereNull('organization_id');

                if ($organizationId !== null) {
                    $query->orWhere('organization_id', $organizationId);
                }
            })
            ->get()
            ->filter(fn (WebhookEndpoint $endpoint): bool => in_array($eventType, $endpoint->event_types, true))
            ->values();
    }
}
