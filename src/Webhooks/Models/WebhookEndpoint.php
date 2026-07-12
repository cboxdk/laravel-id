<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Models;

use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A subscriber endpoint. `organization_id` null = a platform-wide endpoint.
 * The signing secret is stored sealed (Crypto SecretBox) and only opened at
 * delivery time to compute the HMAC signature.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $url
 * @property string $secret_encrypted
 * @property array<int, string> $event_types
 * @property EndpointStatus $status
 */
final class WebhookEndpoint extends Model
{
    use HasUlids;

    protected $table = 'webhook_endpoints';

    protected $guarded = [];

    public function secretContext(): string
    {
        return 'cbox-id:webhook-endpoint:'.$this->id;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'event_types' => 'array',
            'status' => EndpointStatus::class,
        ];
    }
}
