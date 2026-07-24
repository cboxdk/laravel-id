<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Usage\Contracts\ReconcilableScopes;
use Cbox\Id\Organization\Models\Organization;

/**
 * The default {@see ReconcilableScopes}: every organization is a metered scope.
 * Living in the Organization module keeps the Usage kernel free of any reference
 * to the {@see Organization} model — the kernel depends on the contract, and this
 * module (which owns the model) supplies the ids.
 */
class DatabaseReconcilableScopes implements ReconcilableScopes
{
    public function meteredOrganizationIds(): array
    {
        $ids = [];

        foreach (Organization::query()->pluck('id') as $id) {
            if (is_string($id) && $id !== '') {
                $ids[] = $id;
            }
        }

        return $ids;
    }
}
