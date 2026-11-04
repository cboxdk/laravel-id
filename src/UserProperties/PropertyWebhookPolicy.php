<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\UserProperties\Models\PropertyNamespace;
use Cbox\Id\Webhooks\Contracts\WebhookDeliveryPolicy;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;

class PropertyWebhookPolicy implements WebhookDeliveryPolicy
{
    public function __construct(private readonly Subjects $subjects) {}

    public function allows(WebhookEndpoint $endpoint, string $eventType, array $payload): bool
    {
        if (! in_array($eventType, ['user.metadata.updated', 'user.preferences.updated'], true)) {
            return true;
        }
        $namespace = $payload['namespace'] ?? null;
        $user = $payload['user_id'] ?? null;
        if (! is_string($namespace) || ! is_string($user) || ! $this->subjects->isActive($user) || $endpoint->organization_id !== null) {
            return false;
        }
        $record = PropertyNamespace::query()->where('name', $namespace)->first();
        $client = $record?->webhooks[$endpoint->id] ?? null;

        return $record !== null && $record->environment_id === $endpoint->environment_id
            && is_string($client) && in_array($client, $record->readers, true)
            && Client::query()->where('client_id', $client)->whereNull('organization_id')->exists();
    }
}
