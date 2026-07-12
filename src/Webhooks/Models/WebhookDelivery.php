<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Models;

use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $endpoint_id
 * @property string $event_type
 * @property array<string, mixed> $payload
 * @property int $attempt
 * @property DeliveryStatus $status
 * @property int|null $response_code
 * @property Carbon|null $next_retry_at
 * @property Carbon|null $delivered_at
 */
final class WebhookDelivery extends Model
{
    use HasUlids;

    protected $table = 'webhook_deliveries';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'attempt' => 'integer',
            'status' => DeliveryStatus::class,
            'response_code' => 'integer',
            'next_retry_at' => 'datetime',
            'delivered_at' => 'datetime',
        ];
    }
}
