<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Records an accepted assertion id so it can only be consumed once.
 *
 * The replay key is (environment, connection, assertion id), not the assertion id
 * alone: an assertion id is unique only WITHIN its issuing identity provider, so a
 * global unique turned one tenant's valid login into another tenant's "replay". The
 * unique index still does the real work — a replayed assertion is a duplicate-key error,
 * never a read-then-write race.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $connection_id
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
