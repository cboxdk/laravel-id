<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\AuditStreaming\Testing\InteractsWithAuditStreaming;

/**
 * Composition site so the shippable InteractsWithAuditStreaming trait is
 * type-checked by PHPStan (the trait is part of the package's public surface).
 */
final class AuditStreamingHarness
{
    use InteractsWithAuditStreaming;
}
