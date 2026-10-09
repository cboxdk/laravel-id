<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\ValueObjects;

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Hris\Enums\EmploymentStatus;
use Cbox\Id\Directory\Hris\HrisEmployeeMapper;

/**
 * One employee record, read from an HR system and normalised. Everything an HR system
 * knows that matters to an identity: who they are, whether they are employed, from and
 * until when, where they sit and who they report to.
 *
 * Nothing here is an account yet. {@see HrisEmployeeMapper} turns
 * it into the SCIM user the reconciliation already understands — or decides it should not
 * become one (no work email, not started).
 */
readonly class HrisEmployee
{
    /**
     * @param  array<string, scalar|null>  $customAttributes  the fields the directory asked to pass through, keyed by the HR system's own field name
     */
    public function __construct(
        /** The HR system's stable employee id: the directory user's external id. */
        public string $id,
        public ?string $email,
        public EmploymentStatus $status,
        public ?string $firstName = null,
        public ?string $lastName = null,
        public ?string $displayName = null,
        public ?CarbonImmutable $startDate = null,
        public ?CarbonImmutable $terminationDate = null,
        public ?string $departmentId = null,
        public ?string $departmentName = null,
        /** The MANAGER's employee id in the same HR system — an external id, not ours. */
        public ?string $managerId = null,
        public ?string $jobTitle = null,
        public ?string $employeeNumber = null,
        public array $customAttributes = [],
    ) {}

    /** The best available human name: the display name, else first + last, else null. */
    public function name(): ?string
    {
        if ($this->displayName !== null && trim($this->displayName) !== '') {
            return trim($this->displayName);
        }

        $joined = trim(trim((string) $this->firstName).' '.trim((string) $this->lastName));

        return $joined === '' ? null : $joined;
    }
}
