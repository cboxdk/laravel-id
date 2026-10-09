<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Identity\ValueObjects\SmsFactorPolicy;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * The stored form of an environment's {@see SmsFactorPolicy}.
 *
 * @property string $id
 * @property string $environment_id
 * @property bool $enabled
 * @property array<mixed>|null $allowed_countries
 * @property bool $privileged_need_stronger_factor
 */
class SmsFactorPolicyRecord extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'sms_factor_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'allowed_countries' => 'array',
            'privileged_need_stronger_factor' => 'boolean',
        ];
    }

    public function toPolicy(): SmsFactorPolicy
    {
        return new SmsFactorPolicy(
            enabled: $this->enabled,
            allowedCountries: SmsFactorPolicy::normaliseCountries($this->allowed_countries ?? []),
            privilegedNeedStrongerFactor: $this->privileged_need_stronger_factor,
        );
    }
}
