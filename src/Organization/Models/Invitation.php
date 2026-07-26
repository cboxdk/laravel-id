<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Organization\Enums\InvitationStatus;
use Cbox\Id\Organization\Enums\MembershipRole;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A pending invitation to join an organization. Membership is NOT created until
 * the invitee accepts via the emailed link — only the SHA-256 hash of the token
 * is stored. This is what keeps joining consensual: an admin cannot add an
 * existing user to their org without that user's action.
 *
 * ENVIRONMENT-OWNED, like every other credential-bearing model (magic links,
 * password-reset and email-verification tokens, sessions, memberships). Without
 * this the token was a cross-environment primitive: redeeming it on another
 * tenant's host resolved that host's environment, minted a user and a session
 * there, and produced tokens from that environment's issuer. The token is the
 * only proof the accept route has, so it must be bound to the environment that
 * issued it — the hard boundary above the organization tenant.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $email
 * @property MembershipRole $role
 * @property string $token_hash
 * @property InvitationStatus $status
 * @property string|null $invited_by
 * @property Carbon $expires_at
 * @property Carbon|null $accepted_at
 */
class Invitation extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'invitations';

    protected $guarded = [];

    public function isPending(): bool
    {
        return $this->status === InvitationStatus::Pending && $this->expires_at->isFuture();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            // Cast, like the membership it becomes: the invitation carries the
            // authorization level the accepted member will hold, so it must not
            // survive as a raw string that only gets parsed on acceptance.
            'role' => MembershipRole::class,
            'status' => InvitationStatus::class,
            'expires_at' => 'datetime',
            'accepted_at' => 'datetime',
        ];
    }
}
