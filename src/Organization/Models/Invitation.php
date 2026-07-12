<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Organization\Enums\InvitationStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A pending invitation to join an organization. Membership is NOT created until
 * the invitee accepts via the emailed link — only the SHA-256 hash of the token
 * is stored. This is what keeps joining consensual: an admin cannot add an
 * existing user to their org without that user's action.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $email
 * @property string $role
 * @property string $token_hash
 * @property InvitationStatus $status
 * @property string|null $invited_by
 * @property Carbon $expires_at
 * @property Carbon|null $accepted_at
 */
final class Invitation extends Model
{
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
            'status' => InvitationStatus::class,
            'expires_at' => 'datetime',
            'accepted_at' => 'datetime',
        ];
    }
}
