<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris;

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Hris\Enums\EmploymentStatus;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Scim\ScimSchema;

/**
 * Employment → identity: the one place that decides what an HR record means for an account.
 *
 * **Dates win over the status word.** HR systems update a termination date when notice is
 * given and flip the status when payroll closes, sometimes weeks later; a person whose
 * last day has passed is gone whatever the status field still says. A termination date is
 * the LAST day worked, so access ends at the end of that day, not the start of it. A start
 * date in the future is a pre-hire, who gets an account `cbox-id.directory.hris.pre_hire_days`
 * days ahead (default 0: on the day).
 *
 * **The record becomes a SCIM user** — the same shape a SCIM push stores, so everything
 * downstream of the directory (group→role mappings, the console, erasure) sees nothing new:
 * core `name`/`emails`/`title`, the RFC 7643 enterprise extension for `employeeNumber`,
 * `department` and `manager` (whose `value` is the manager's HR employee id — the
 * manager's external id in this directory), and {@see self::SCHEMA} for what SCIM has no
 * word for: employment status, start and termination dates, the department's id, and the
 * custom attributes the directory asked to pass through.
 */
final class HrisEmployeeMapper
{
    /** The extension carrying what an HR system knows and SCIM has no attribute for. */
    public const string SCHEMA = 'urn:cbox-id:params:scim:schemas:extension:hris:1.0:User';

    public function __construct(
        private readonly int $preHireDays = 0,
        private readonly ?CarbonImmutable $now = null,
    ) {}

    public static function fromConfig(): self
    {
        $days = config('cbox-id.directory.hris.pre_hire_days', 0);

        return new self(max(0, is_numeric($days) ? (int) $days : 0));
    }

    /**
     * The status that actually applies today, with the dates applied over the word.
     */
    public function effectiveStatus(HrisEmployee $employee): EmploymentStatus
    {
        $now = $this->now ?? CarbonImmutable::now();

        if ($employee->terminationDate !== null && $employee->terminationDate->endOfDay()->lt($now)) {
            return EmploymentStatus::Terminated;
        }

        if ($employee->status === EmploymentStatus::Terminated || $employee->status === EmploymentStatus::Inactive) {
            return $employee->status;
        }

        if ($employee->startDate !== null) {
            $opens = $employee->startDate->startOfDay()->subDays($this->preHireDays);

            if ($opens->gt($now)) {
                return EmploymentStatus::PreHire;
            }

            // Started, whatever the HR system still calls it ("onboarding").
            return $employee->status === EmploymentStatus::PreHire ? EmploymentStatus::Active : $employee->status;
        }

        return $employee->status;
    }

    public function grantsAccess(HrisEmployee $employee): bool
    {
        return $this->effectiveStatus($employee)->grantsAccess();
    }

    /**
     * The SCIM user this employee is, or null when there is no work email to make one from.
     */
    public function toScimUser(HrisEmployee $employee, DirectoryProvider $provider): ?ScimUser
    {
        $email = $employee->email === null ? null : trim($employee->email);

        if ($email === null || $email === '' || ! str_contains($email, '@')) {
            return null;
        }

        $status = $this->effectiveStatus($employee);

        return new ScimUser(
            externalId: $employee->id,
            userName: $email,
            email: $email,
            displayName: $employee->name(),
            active: $status->grantsAccess(),
            raw: $this->resource($employee, $provider, $email, $status),
        );
    }

    /**
     * The department key a group is built from: the department's id when the HR system has
     * one, its folded name when it only has a name (BambooHR files people under a name).
     */
    public static function departmentKey(HrisEmployee $employee): ?string
    {
        if ($employee->departmentId !== null && trim($employee->departmentId) !== '') {
            return trim($employee->departmentId);
        }

        if ($employee->departmentName !== null && trim($employee->departmentName) !== '') {
            return 'name:'.mb_strtolower(trim($employee->departmentName));
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    private function resource(HrisEmployee $employee, DirectoryProvider $provider, string $email, EmploymentStatus $status): array
    {
        $name = array_filter([
            'givenName' => $employee->firstName,
            'familyName' => $employee->lastName,
            'formatted' => $employee->name(),
        ], static fn (?string $v): bool => $v !== null && trim($v) !== '');

        $enterprise = array_filter([
            'employeeNumber' => $employee->employeeNumber,
            'department' => $employee->departmentName,
            'manager' => $employee->managerId === null ? null : ['value' => $employee->managerId],
        ], static fn (mixed $v): bool => $v !== null);

        return array_filter([
            'schemas' => [ScimSchema::USER_URN, ScimSchema::ENTERPRISE_URN, self::SCHEMA],
            'externalId' => $employee->id,
            'userName' => $email,
            'name' => $name === [] ? null : $name,
            'displayName' => $employee->name(),
            'title' => $employee->jobTitle,
            'emails' => [['value' => $email, 'type' => 'work', 'primary' => true]],
            'active' => $status->grantsAccess(),
            ScimSchema::ENTERPRISE_URN => $enterprise === [] ? null : $enterprise,
            self::SCHEMA => [
                'provider' => $provider->value,
                'employmentStatus' => $status->value,
                'reportedStatus' => $employee->status->value,
                'startDate' => $employee->startDate?->toDateString(),
                'terminationDate' => $employee->terminationDate?->toDateString(),
                'departmentId' => self::departmentKey($employee),
                'managerId' => $employee->managerId,
                'customAttributes' => $employee->customAttributes,
            ],
        ], static fn (mixed $v): bool => $v !== null);
    }
}
