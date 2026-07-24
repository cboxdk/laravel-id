<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Organization\Enums\OrganizationType;

readonly class NewOrganization
{
    /**
     * @param  array<string, mixed>  $settings
     */
    public function __construct(
        public string $name,
        public string $slug,
        public OrganizationType $type = OrganizationType::Customer,
        public ?string $parentId = null,
        public array $settings = [],
    ) {}
}
