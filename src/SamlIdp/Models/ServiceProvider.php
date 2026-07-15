<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Enums\ServiceProviderStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A relying SAML service provider (Salesforce, Workday, AWS, …) that federates to
 * this platform as its Identity Provider. Environment-owned: an SP registered in
 * one environment is invisible to every other, so the same EntityID may be used
 * by different tenants without collision.
 *
 * `acs_url` is the ONLY location an assertion for this SP is ever POSTed to — it
 * is matched exactly (no wildcards, no request-supplied override), which is the
 * open-redirect / assertion-to-attacker defense. `certificate` is the SP's
 * signing certificate, used to verify signed AuthnRequests when
 * `want_authn_requests_signed` is set.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $entity_id
 * @property string $acs_url
 * @property NameIdFormat $name_id_format
 * @property string $name_id_attribute
 * @property array<string, string> $attribute_mappings
 * @property string|null $certificate
 * @property bool $want_authn_requests_signed
 * @property ServiceProviderStatus $status
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class ServiceProvider extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_service_providers';

    protected $guarded = [];

    public function isActive(): bool
    {
        return $this->status === ServiceProviderStatus::Active;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'name_id_format' => NameIdFormat::class,
            'attribute_mappings' => 'array',
            'want_authn_requests_signed' => 'boolean',
            'status' => ServiceProviderStatus::class,
        ];
    }
}
