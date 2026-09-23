<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * A scope an {@see Api} owns. `key` is unique per environment — a token request names a
 * scope by key alone, so it must identify exactly one API. `tenant_requestable` says
 * whether a client owned by an organization may hold it when the API is
 * environment-owned (a tenant's own API is always requestable by that tenant only).
 *
 * @property string $id
 * @property string $environment_id
 * @property string $api_id
 * @property string $key
 * @property string|null $description
 * @property bool $tenant_requestable
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ApiScope extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_api_scopes';

    protected $guarded = [];

    /**
     * @return BelongsTo<Api, $this>
     */
    public function api(): BelongsTo
    {
        return $this->belongsTo(Api::class, 'api_id');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'tenant_requestable' => 'boolean',
        ];
    }
}
