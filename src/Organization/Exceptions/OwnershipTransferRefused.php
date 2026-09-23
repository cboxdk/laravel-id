<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use Cbox\Id\Organization\Enums\OwnershipTransferRefusal;
use RuntimeException;

/**
 * An ownership transfer the organization's state does not allow. The {@see $reason} is the
 * stable, machine-readable half; the message is the human one.
 */
class OwnershipTransferRefused extends RuntimeException
{
    public function __construct(
        public readonly OwnershipTransferRefusal $reason,
        public readonly string $organizationId,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function notOwner(string $organizationId, string $userId): self
    {
        return new self(
            OwnershipTransferRefusal::NotOwner,
            $organizationId,
            "User [{$userId}] is not an active owner of organization [{$organizationId}], so has no ownership to transfer.",
        );
    }

    public static function targetNotMember(string $organizationId, string $userId): self
    {
        return new self(
            OwnershipTransferRefusal::TargetNotMember,
            $organizationId,
            "User [{$userId}] is not a member of organization [{$organizationId}]. Ownership can only be transferred to an existing member.",
        );
    }

    public static function targetNotActive(string $organizationId, string $userId): self
    {
        return new self(
            OwnershipTransferRefusal::TargetNotActive,
            $organizationId,
            "User [{$userId}] is a member of organization [{$organizationId}] but not an active one. Ownership can only be transferred to an active member.",
        );
    }

    public static function sameMember(string $organizationId): self
    {
        return new self(
            OwnershipTransferRefusal::SameMember,
            $organizationId,
            "Ownership of organization [{$organizationId}] cannot be transferred to the member who already holds it.",
        );
    }
}
