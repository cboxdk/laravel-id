<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Kernel\Audit\Enums\ActorType;

/**
 * Who revoked a customer API key, for the audit trail. The holder revoking their own
 * key, an organization administrator revoking a colleague's, and an environment API key
 * revoking one through the management API are three different answers to "who did this".
 */
readonly class ApiKeyActor
{
    public function __construct(
        public ActorType $type = ActorType::System,
        public ?string $id = null,
    ) {}

    /** A person — the holder, or an administrator acting on the key. */
    public static function user(string $userId): self
    {
        return new self(ActorType::User, $userId);
    }

    /** A machine credential, e.g. the environment API key behind the management API. */
    public static function service(string $credentialId): self
    {
        return new self(ActorType::Service, $credentialId);
    }

    public static function system(): self
    {
        return new self;
    }
}
