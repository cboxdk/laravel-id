<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Enums;

/**
 * What a de-provision (e.g. a membership removed) does to the remote record.
 * `Deactivate` (SCIM `active` = false) is the reversible, audit-friendly default;
 * `Delete` issues DELETE /Users/{id} for apps that require hard removal.
 */
enum DeprovisionPolicy: string
{
    case Deactivate = 'deactivate';
    case Delete = 'delete';
}
