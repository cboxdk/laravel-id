<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A DNS-verified email domain owned by an organization. Once `verified_at` is
 * set, users with an email at this domain can be routed to the org's SSO
 * (home-realm discovery). `capture` is the optional gate that additionally forces
 * matching users into the org's auth policy — enforced by the host, not here.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $domain
 * @property string $verification_token
 * @property Carbon|null $verified_at
 * @property bool $capture
 */
class VerifiedDomain extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'verified_domains';

    protected $guarded = [];

    public function isVerified(): bool
    {
        return $this->verified_at !== null;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime',
            'capture' => 'boolean',
        ];
    }
}
