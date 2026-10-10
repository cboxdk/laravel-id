<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

/**
 * One record a pull could not reconcile, and why — in words that hold no personal data.
 *
 * The external id is the provider's own employee id, which an administrator can look up in
 * the provider; the reason never carries the email or name, because it is stored on the
 * directory and shown in a console. `externalId` is null for a failure about the run rather
 * than a record (a department that could not be filed, a deprovisioning that was refused).
 */
readonly class SyncFailure
{
    public function __construct(
        public ?string $externalId,
        public string $reason,
    ) {}

    /**
     * @return array{external_id: string|null, reason: string}
     */
    public function toArray(): array
    {
        return ['external_id' => $this->externalId, 'reason' => $this->reason];
    }
}
