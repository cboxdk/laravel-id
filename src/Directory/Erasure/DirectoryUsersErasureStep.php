<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Erasure;

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;

/**
 * The inbound-SCIM copy of the person: the directory's resource as it was pushed to us,
 * which is the upstream IdP's whole record of them. Deleted.
 *
 * Honest limit: the upstream directory still has them. If it pushes the user again, a
 * new subject is provisioned — erasure here does not reach back into the customer's IdP.
 */
class DirectoryUsersErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'directory.users';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        return ErasureStepResult::of($this->name(), [
            'directory_users' => DirectoryUser::query()->where('user_id', $request->subjectId)->toBase()->delete(),
        ]);
    }
}
