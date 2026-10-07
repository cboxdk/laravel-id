<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Erasure;

use Cbox\Id\AccessControl\Models\EnvironmentRoleAssignment;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Illuminate\Support\Facades\Schema;

/**
 * Role grants of the built-in RBAC that outlive a membership removal: environment-wide
 * ("everywhere") assignments, and any per-organization assignment left behind.
 *
 * Organization-scoped grants normally go with the membership (the memberships step runs
 * first and removes them through the membership service); this catches the rest. On a
 * deployment that brings its own RBAC the tables do not exist and the step reports so —
 * the external authorization system is the host's to erase from.
 */
class RoleGrantsErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'access_control.roles';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        if (! Schema::hasTable('role_assignments')) {
            return ErasureStepResult::of($this->name(), [], 'built-in RBAC not installed; erase role grants in your own authorization system');
        }

        return ErasureStepResult::of($this->name(), [
            'role_assignments' => RoleAssignment::query()->where('user_id', $request->subjectId)->toBase()->delete(),
            'environment_role_assignments' => EnvironmentRoleAssignment::query()->where('user_id', $request->subjectId)->toBase()->delete(),
        ]);
    }
}
