<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Models;

use Cbox\Id\Governance\Enums\AccessKind;
use Cbox\Id\Governance\Enums\ReviewDecision;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One reviewable access grant within a campaign: a single subject's role
 * assignment or organization membership, captured at snapshot time and awaiting a
 * certify / revoke decision.
 *
 * `access_ref` is the grant's discriminator: the `role_id` for a role, or the
 * membership `role` string for a membership. `organization_id` is where the grant
 * physically lives — for a role it is the assignment's own org (which may be an
 * ancestor of the campaign's org), so the revoke on close targets the right row.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $campaign_id
 * @property AccessKind $access_type
 * @property string $subject_id
 * @property string $access_ref
 * @property string $organization_id
 * @property string|null $source
 * @property string|null $reviewer_id
 * @property ReviewDecision $decision
 * @property string|null $decided_by
 * @property Carbon|null $decided_at
 * @property string|null $note
 * @property bool $applied
 * @property string|null $application_note
 */
final class CertificationItem extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'governance_certification_items';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'access_type' => AccessKind::class,
            'decision' => ReviewDecision::class,
            'decided_at' => 'datetime',
            'applied' => 'boolean',
        ];
    }
}
