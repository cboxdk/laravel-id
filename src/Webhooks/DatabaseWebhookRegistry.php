<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Contracts\WebhookSigningSchemes;
use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Cbox\Id\Webhooks\Exceptions\UnknownWebhookEvent;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Cbox\Id\Webhooks\Support\StandardWebhookSignature;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class DatabaseWebhookRegistry implements WebhookRegistry, WebhookSigningSchemes
{
    public function __construct(private readonly SecretBox $secretBox) {}

    /**
     * The trailing `$scheme` is an addition on this class only — {@see WebhookRegistry}
     * keeps its signature; {@see WebhookSigningSchemes::registerWithScheme()} is the
     * contract route to the same thing.
     */
    public function register(string $organizationId, string $url, array $eventTypes, SignatureScheme $scheme = SignatureScheme::Cbox): RegisteredEndpoint
    {
        return $this->store($organizationId, $url, $eventTypes, $scheme);
    }

    public function registerForEnvironment(string $url, array $eventTypes, SignatureScheme $scheme = SignatureScheme::Cbox): RegisteredEndpoint
    {
        return $this->store(null, $url, $eventTypes, $scheme);
    }

    public function registerWithScheme(string $organizationId, string $url, array $eventTypes, SignatureScheme $scheme): RegisteredEndpoint
    {
        return $this->store($organizationId, $url, $eventTypes, $scheme);
    }

    public function registerForEnvironmentWithScheme(string $url, array $eventTypes, SignatureScheme $scheme): RegisteredEndpoint
    {
        return $this->store(null, $url, $eventTypes, $scheme);
    }

    public function changeSignatureScheme(string $endpointId, ?string $organizationId, SignatureScheme $scheme): ?WebhookEndpoint
    {
        // The same exact-owner match as pause(): an id learned from another organization
        // must not let a tenant change how that organization's deliveries are signed —
        // flipping a receiver's scheme is as good as silencing it until they notice.
        $endpoint = $this->owned($endpointId, $organizationId);

        if ($endpoint === null) {
            return null;
        }

        $endpoint->signature_scheme = $scheme;
        $endpoint->save();

        return $endpoint;
    }

    /**
     * @param  list<string>  $eventTypes
     */
    private function store(?string $organizationId, string $url, array $eventTypes, SignatureScheme $scheme): RegisteredEndpoint
    {
        // A null organization here is PLATFORM-wide coverage — matching() delivers every
        // org's events to it. It is unreachable except through registerForEnvironment(),
        // which is the whole point of splitting the two.
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

        // The Cbox scheme's secret is exactly what it has always been — 64 hex characters,
        // used as the HMAC key as written. A Standard Webhooks endpoint is minted in the
        // spec's own `whsec_` form, so its owner can paste it into any Standard Webhooks
        // library without converting anything.
        $secret = match ($scheme) {
            SignatureScheme::Cbox => bin2hex(random_bytes(32)),
            SignatureScheme::StandardWebhooks => StandardWebhookSignature::mintSecret(),
        };

        $endpoint = new WebhookEndpoint;
        $endpoint->id = (string) Str::ulid();
        $endpoint->fill([
            'organization_id' => $organizationId,
            'url' => $url,
            'event_types' => $eventTypes,
            'status' => EndpointStatus::Active,
            'signature_scheme' => $scheme,
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
        $this->owned($endpointId, $organizationId)?->update(['status' => EndpointStatus::Paused]);
    }

    /** The endpoint with this id, only if this exact owner (null = the environment) holds it. */
    private function owned(string $endpointId, ?string $organizationId): ?WebhookEndpoint
    {
        return WebhookEndpoint::query()
            ->whereKey($endpointId)
            ->where(fn ($query) => $organizationId === null
                ? $query->whereNull('organization_id')
                : $query->where('organization_id', $organizationId))
            ->first();
    }

    public function matching(?string $organizationId, string $eventType): Collection
    {
        // The subscription test stays in PHP: `event_types` is a JSON column, and a
        // portable containment predicate across SQLite, MySQL and PostgreSQL is not one
        // expression. The set is an environment's endpoints, not a table scan.
        return $this->forOrganization($organizationId)
            ->filter(fn (WebhookEndpoint $endpoint): bool => in_array($eventType, $endpoint->event_types, true)
                || in_array(WebhookEventType::WILDCARD, $endpoint->event_types, true))
            ->values();
    }

    public function forOrganization(?string $organizationId): Collection
    {
        return WebhookEndpoint::query()
            ->where('status', EndpointStatus::Active->value)
            ->where(function ($query) use ($organizationId): void {
                $query->whereNull('organization_id');

                if ($organizationId !== null) {
                    $query->orWhere('organization_id', $organizationId);
                }
            })
            ->get();
    }
}
