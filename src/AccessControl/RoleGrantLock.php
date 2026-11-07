<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Support\Facades\DB;
use LogicException;

/** @internal Shared by manual grants, revocations and directory reconciliation. */
final class RoleGrantLock
{
    public static function forSubject(string $userId): void
    {
        if (DB::transactionLevel() < 1) {
            throw new LogicException('Role grants require an enclosing transaction.');
        }
        $key = [
            'environment_id' => app(EnvironmentContext::class)->requireEnvironment()->environmentKey(),
            'subject_id' => $userId,
        ];
        DB::table('role_grant_subject_locks')->insertOrIgnore($key);
        DB::table('role_grant_subject_locks')->where($key)->lockForUpdate()->first();
    }
}
