<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Provisioning\Enums\OperationStatus;
use Cbox\Id\Provisioning\Enums\OperationType;
use Cbox\Id\Provisioning\Models\ProvisioningOperation;
use Cbox\Id\Provisioning\OutboxProvisioningService;

/**
 * The outbound-SCIM queue's copy of the person.
 *
 * Every queued operation carries a snapshot of the subject's email and name, taken when
 * it was enqueued so delivery is self-contained. Two things follow:
 *
 * - An UNDELIVERED create/update/reactivate would re-create the person in a downstream
 *   app after they were erased. Those are cancelled (deleted).
 * - Every other operation for them — delivered, or a deprovision still pending — keeps
 *   its row for the delivery history but loses its snapshot.
 *
 * The downstream DELETE itself is driven by the `user.erased` event the eraser emits
 * ({@see OutboxProvisioningService}), to every connection that
 * holds a remote record of them, whatever its deprovision policy.
 */
class ProvisioningErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'provisioning.queue';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $cancelled = ProvisioningOperation::query()
            ->where('user_id', $request->subjectId)
            ->whereIn('type', [OperationType::Upsert->value, OperationType::Reactivate->value])
            ->whereIn('status', [OperationStatus::Pending->value, OperationStatus::Failed->value])
            ->toBase()->delete();

        $scrubbed = 0;

        foreach (ProvisioningOperation::query()->where('user_id', $request->subjectId)->cursor() as $operation) {
            if ($operation->payload !== []) {
                $operation->payload = [];
                $operation->save();
                $scrubbed++;
            }
        }

        return ErasureStepResult::of($this->name(), [
            'operations_cancelled' => $cancelled,
            'operation_snapshots_scrubbed' => $scrubbed,
        ]);
    }
}
