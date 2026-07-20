<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Models;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A persisted outbox row. Written in the same transaction as the state change
 * it describes; delivered asynchronously by the relay ({@see EventBus::flushPending()}).
 *
 * @property string $id
 * @property string $type
 * @property string|null $organization_id
 * @property string|null $environment_id
 * @property array<string, mixed> $payload
 * @property Carbon $occurred_at
 * @property Carbon|null $dispatched_at
 */
class Event extends Model
{
    use HasUlids;

    public $timestamps = false;

    protected $table = 'events';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'occurred_at' => 'datetime',
            'dispatched_at' => 'datetime',
        ];
    }
}
