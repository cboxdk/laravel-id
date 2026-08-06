<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Organization\Testing\InteractsWithOrganizations;

/**
 * Composition site so the shippable InteractsWithOrganizations trait is type-checked.
 */
final class OrganizationHarness
{
    use InteractsWithOrganizations;
}
