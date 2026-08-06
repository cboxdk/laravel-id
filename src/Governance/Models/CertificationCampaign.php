<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Models;

use Cbox\Id\Governance\Enums\CampaignStatus;
use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An access-certification campaign: a point-in-time snapshot of the access grants
 * within one organization, put in front of reviewers to certify or revoke.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $name
 * @property CampaignStatus $status
 * @property PendingPolicy $pending_policy
 * @property Carbon|null $due_at
 * @property string|null $created_by
 * @property Carbon|null $closed_at
 */
class CertificationCampaign extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'governance_campaigns';

    protected $guarded = [];

    public function isClosed(): bool
    {
        return $this->status === CampaignStatus::Closed;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => CampaignStatus::class,
            'pending_policy' => PendingPolicy::class,
            'due_at' => 'datetime',
            'closed_at' => 'datetime',
        ];
    }
}
