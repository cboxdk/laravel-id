<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\ValueObjects\NewOrganization;

interface Organizations
{
    public function create(NewOrganization $input): Organization;

    public function find(string $id): ?Organization;

    public function bySlug(string $slug): ?Organization;
}
