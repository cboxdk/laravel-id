<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Records an accepted assertion id so it can only be consumed once. The unique
 * index on `assertion_id` turns a replayed assertion into a duplicate-key error.
 *
 * @property string $id
 * @property string $assertion_id
 * @property Carbon $expires_at
 */
class ConsumedAssertion extends Model
{
    use HasUlids;

    protected $table = 'consumed_assertions';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }
}
