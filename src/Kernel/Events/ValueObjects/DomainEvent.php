<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\ValueObjects;

/**
 * A domain event to append to the outbox. `organizationId` tags the event with
 * its tenant (null for system-level events).
 */
final readonly class DomainEvent
{
    /**
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public string $type,
        public array $payload = [],
        public ?string $organizationId = null,
    ) {}
}
