<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\OAuthServer\ValueObjects\ApiAudience;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * An API (resource server) registered in an environment. `identifier` is the absolute
 * URI a token names in `aud` — unique per environment. `organization_id` is the owner
 * (null = environment-owned). `client_id` optionally names the app whose declared roles
 * and permissions the API enforces: a token audienced to this API carries THAT app's
 * RBAC, not the requesting client's.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string|null $client_id
 * @property string $identifier
 * @property string $name
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class Api extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_apis';

    protected $guarded = [];

    /**
     * @return HasMany<ApiScope, $this>
     */
    public function scopes(): HasMany
    {
        return $this->hasMany(ApiScope::class, 'api_id')->orderBy('key');
    }

    public function isEnvironmentOwned(): bool
    {
        return $this->organization_id === null;
    }

    public function audience(): ApiAudience
    {
        return new ApiAudience($this->id, $this->identifier, $this->organization_id, $this->client_id);
    }
}
