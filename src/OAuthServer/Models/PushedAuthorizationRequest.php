<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A pushed authorization request (RFC 9126): its parameters stored server-side and
 * referenced by an opaque, single-use request_uri.
 *
 * @property string $id
 * @property string $request_uri
 * @property string $client_id
 * @property array<string, mixed> $params
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 */
final class PushedAuthorizationRequest extends Model
{
    use HasUlids;

    protected $table = 'pushed_authorization_requests';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'params' => 'array',
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
