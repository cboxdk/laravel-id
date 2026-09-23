<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\ValueObjects;

use Cbox\Id\Kernel\Audit\Enums\ActorType;

/**
 * Who is performing a change, handed to a service that audits it.
 *
 * A service knows WHAT happened; only its caller knows who asked. So a service that
 * records its own trail takes one of these from the caller rather than guessing, and
 * records `system` when none is given — which is honest about a change made by a job, a
 * migration or a command, and wrong for a change a person made. Consoles should always
 * pass one.
 */
readonly class AuditActor
{
    public function __construct(
        public ActorType $type = ActorType::System,
        public ?string $id = null,
    ) {}

    public static function system(): self
    {
        return new self;
    }

    /** An end user inside the environment (a subject). */
    public static function user(string $userId): self
    {
        return new self(ActorType::User, $userId);
    }

    /** One of the customer's own people acting on the management plane. */
    public static function organizationMember(string $memberId): self
    {
        return new self(ActorType::OrganizationMember, $memberId);
    }

    /** A platform operator. */
    public static function operator(string $operatorId): self
    {
        return new self(ActorType::Operator, $operatorId);
    }

    /** A machine credential acting for itself — an OAuth client, an API key. */
    public static function service(string $serviceId): self
    {
        return new self(ActorType::Service, $serviceId);
    }
}
