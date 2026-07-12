<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;
use Cbox\Id\Organization\Enums\OrganizationStatus;
use Cbox\Id\Organization\Enums\OrganizationType;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A tenant — the isolation boundary of the platform. Organizations form a
 * management tree (reseller → customer, holding → subsidiary) via `parent_id`
 * and the `organization_closure` table.
 *
 * This is the production {@see Tenant}: its key is its own id.
 *
 * @property string $id
 * @property string $name
 * @property string $slug
 * @property string|null $parent_id
 * @property OrganizationType $type
 * @property OrganizationStatus $status
 * @property array<string, mixed> $settings
 */
final class Organization extends Model implements Tenant
{
    use HasUlids;

    protected $table = 'organizations';

    protected $guarded = [];

    public function tenantKey(): string
    {
        return $this->id;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => OrganizationType::class,
            'status' => OrganizationStatus::class,
            'settings' => 'array',
        ];
    }
}
