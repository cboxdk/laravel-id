<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Enums;

/**
 * Who a vault secret belongs to. A closed set, so an owner can never be an
 * arbitrary caller-supplied label — the ownership field is the vault's tenancy
 * boundary, and a boundary you can spell freely is not a boundary.
 */
enum VaultOwnerType: string
{
    case Organization = 'organization';
    case User = 'user';
}
