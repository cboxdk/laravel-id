<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Audit\Testing\InteractsWithAudit;

/**
 * Composition site so the shippable InteractsWithAudit trait is type-checked.
 */
final class AuditHarness
{
    use InteractsWithAudit;
}
