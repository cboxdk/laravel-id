<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Enums;

/**
 * The kind of change to propagate to a downstream app, translated from a
 * platform domain event. Each maps to one SCIM 2.0 outcome:
 *
 *  - {@see Upsert}      → POST /Users (create) or PATCH /Users/{id} (update) —
 *                         the statefully-reconciled create-or-update.
 *  - {@see Deactivate}  → PATCH replace `active` = false (keep the remote record).
 *  - {@see Reactivate}  → PATCH replace `active` = true.
 *  - {@see Deprovision} → PATCH `active` = false OR DELETE, per the connection's
 *                         de-provision policy (e.g. membership removed).
 */
enum OperationType: string
{
    case Upsert = 'upsert';
    case Deactivate = 'deactivate';
    case Reactivate = 'reactivate';
    case Deprovision = 'deprovision';
}
