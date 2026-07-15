<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Models;

use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Enums\ConnectionStatus;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A downstream app to provision users OUT to, over ITS SCIM 2.0 endpoint. The
 * mirror of an inbound {@see Directory}: there the
 * platform is the SCIM server receiving provisioning; here it is the SCIM client
 * pushing it.
 *
 * Environment-owned: a connection belongs to exactly one environment, so a
 * connection in env-A can only ever provision env-A's subjects — the hard scope
 * makes cross-environment provisioning structurally impossible. `organization_id`
 * null = an environment-wide connection (still fenced to its one environment).
 *
 * The bearer token / OAuth client secret is stored sealed (Crypto SecretBox) and
 * only opened at delivery time to build the Authorization header; it is never
 * returned in plaintext again and never written to an error/dead-letter row.
 *
 * `scope` selects which subjects are in range (an empty organization list = every
 * subject in the environment; a non-empty list = only members of those orgs).
 * `attribute_mapping` maps platform user attributes → SCIM `User` schema paths.
 * The `consecutive_failures` / `circuit_opened_at` / `last_success_at` columns
 * back the per-connection circuit breaker.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string $name
 * @property string $base_url
 * @property AuthScheme $auth_scheme
 * @property string $auth_secret_encrypted
 * @property array<string, mixed> $auth_config
 * @property array<string, mixed> $attribute_mapping
 * @property array<string, mixed> $scope
 * @property DeprovisionPolicy $deprovision_policy
 * @property ConnectionStatus $status
 * @property int $consecutive_failures
 * @property Carbon|null $circuit_opened_at
 * @property Carbon|null $last_success_at
 * @property string|null $last_error
 */
class ProvisioningConnection extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'provisioning_connections';

    protected $guarded = [];

    /**
     * The AAD context binding the sealed auth secret to THIS connection row, so a
     * ciphertext sealed for one connection cannot be opened against another.
     */
    public function secretContext(): string
    {
        return 'cbox-id:provisioning-connection:'.$this->id;
    }

    /**
     * The organizations this connection provisions. Empty ⇒ environment-wide
     * (every subject in the environment).
     *
     * @return list<string>
     */
    public function scopeOrganizationIds(): array
    {
        $ids = $this->scope['organization_ids'] ?? [];

        if (! is_array($ids)) {
            return [];
        }

        return array_values(array_filter($ids, is_string(...)));
    }

    public function isEnvironmentWide(): bool
    {
        return $this->scopeOrganizationIds() === [];
    }

    /** The `/Users` collection endpoint (base URL without a trailing slash). */
    public function usersEndpoint(): string
    {
        return rtrim($this->base_url, '/').'/Users';
    }

    public function userEndpoint(string $remoteId): string
    {
        return $this->usersEndpoint().'/'.rawurlencode($remoteId);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'auth_scheme' => AuthScheme::class,
            'auth_config' => 'array',
            'attribute_mapping' => 'array',
            'scope' => 'array',
            'deprovision_policy' => DeprovisionPolicy::class,
            'status' => ConnectionStatus::class,
            'consecutive_failures' => 'integer',
            'circuit_opened_at' => 'datetime',
            'last_success_at' => 'datetime',
        ];
    }
}
