<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\ValueObjects;

use Cbox\Id\Kernel\Audit\Enums\ActorType;

/**
 * A security-relevant event to be appended to the audit trail.
 *
 * `organizationId` selects the chain: a tenant key scopes it to that tenant's
 * trail; null records it on the system trail.
 */
final readonly class AuditEvent
{
    /**
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public string $action,
        public ActorType $actorType = ActorType::System,
        public ?string $actorId = null,
        public ?string $organizationId = null,
        public ?string $targetType = null,
        public ?string $targetId = null,
        public array $context = [],
        public ?string $ip = null,
    ) {}

    /**
     * @param  array<string, mixed>  $context
     */
    public static function forUser(string $action, string $userId, ?string $organizationId = null, array $context = []): self
    {
        return new self(
            action: $action,
            actorType: ActorType::User,
            actorId: $userId,
            organizationId: $organizationId,
            context: $context,
        );
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public static function forSystem(string $action, array $context = []): self
    {
        return new self(action: $action, actorType: ActorType::System, context: $context);
    }
}
