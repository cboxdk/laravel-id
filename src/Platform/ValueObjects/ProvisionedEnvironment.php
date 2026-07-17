<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;

/**
 * The result of provisioning a new environment (IdP): the environment itself, its
 * owner (the signed-up admin), and their first organization — all created inside the
 * new environment's tenant scope.
 */
final readonly class ProvisionedEnvironment
{
    public function __construct(
        public Environment $environment,
        public Subject $owner,
        public Organization $organization,
    ) {}
}
