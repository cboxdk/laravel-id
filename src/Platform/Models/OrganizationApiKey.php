<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Organization;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * An organization API key — a hashed, role-carrying credential for the management
 * management plane. Only the hash is persisted; the plaintext lives only in the
 * response that created it.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $name
 * @property string $prefix
 * @property string $token_hash
 * @property MembershipRole $role
 * @property Carbon|null $last_used_at
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 */
class OrganizationApiKey extends Model
{
    use HasUlids;

    protected $table = 'organization_api_keys';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['token_hash'];

    /** Usable only while neither revoked nor past its expiry. */
    public function isActive(): bool
    {
        if ($this->revoked_at !== null) {
            return false;
        }

        return $this->expires_at === null || $this->expires_at->isFuture();
    }

    /**
     * The organization this key acts for.
     *
     * The related query IS environment-scoped ({@see Organization} is environment-owned),
     * so it resolves only from inside the platform root and returns null anywhere else.
     * That is the correct failure: a tenant host has no business reading the row that
     * identifies the platform's own customer.
     *
     * @return BelongsTo<Organization, $this>
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => MembershipRole::class,
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }
}
