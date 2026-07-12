<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Testing;

use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Support\Str;

/**
 * Convenience for creating organizations in tests, with a unique slug by default:
 *
 *     $org = $this->makeOrganization('Northwind');
 *     $child = $this->makeOrganization('Sub', parentId: $org->id);
 */
trait InteractsWithOrganizations
{
    protected function makeOrganization(
        string $name = 'Acme Inc',
        ?string $slug = null,
        ?string $parentId = null,
        OrganizationType $type = OrganizationType::Customer,
    ): Organization {
        return app(Organizations::class)->create(new NewOrganization(
            name: $name,
            slug: $slug ?? Str::slug($name).'-'.Str::lower(Str::random(6)),
            type: $type,
            parentId: $parentId,
        ));
    }
}
