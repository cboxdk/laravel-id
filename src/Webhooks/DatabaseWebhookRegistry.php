<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Cbox\Id\Webhooks\Exceptions\UnknownWebhookEvent;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class DatabaseWebhookRegistry implements WebhookRegistry
{
    public function __construct(private readonly SecretBox $secretBox) {}

    public function register(?string $organizationId, string $url, array $eventTypes): RegisteredEndpoint
    {
        // NOTE on organizationId === null: that is PLATFORM-wide coverage — matching()
        // delivers every org's events to it. Only an operator-plane caller may pass null;
        // the tenant console always supplies its own org. See the console call sites.
        // SSRF guard: refuse endpoints that point at non-public addresses.
        SafeWebhookUrl::assert($url);

        // Event types are open-ended — the domain (and its plugins) emit far more
        // than any curated list could track, so a subscription may name ANY non-empty
        // type. WebhookEventType stays a *documented* catalog (the console picker, the
        // `*` wildcard) rather than a hard allow-list that would reject a legitimate
        // event and break the subscriber. Only an empty/blank type is refused.
        foreach ($eventTypes as $eventType) {
            if (trim($eventType) === '') {
                throw UnknownWebhookEvent::forType($eventType);
            }
        }

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

    public function pause(string $endpointId, ?string $organizationId): void
    {
        // Exact owner match, like the inline-hook registry. Resolving by id alone let an
        // org admin who learned another org's endpoint id disable that org's webhooks —
        // and pass null to act as the environment, so a tenant cannot silence the
        // operator's own platform-wide endpoints either.
        $endpoint = WebhookEndpoint::query()
            ->whereKey($endpointId)
            ->where(fn ($query) => $organizationId === null
                ? $query->whereNull('organization_id')
                : $query->where('organization_id', $organizationId))
            ->first();

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
            ->filter(fn (WebhookEndpoint $endpoint): bool => in_array($eventType, $endpoint->event_types, true)
                || in_array(WebhookEventType::WILDCARD, $endpoint->event_types, true))
            ->values();
    }
}
