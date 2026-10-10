<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\Enums;

use Cbox\Id\Directory\Hris\HrisEmployeeMapper;

/**
 * Where a person stands with their employer, normalised across HR systems.
 *
 * Every HR system has its own vocabulary — BambooHR says `Active`/`Inactive`, HiBob
 * `Employed`/`Terminated`, Personio `active`/`onboarding`/`leave`/`inactive`, Workday a
 * boolean and a date — and each connector folds its own into these five. The dates on the
 * record still win over the word: an employee whose termination date has passed is
 * terminated whatever the status field still says, because HR updates the date first and
 * the status when somebody remembers ({@see HrisEmployeeMapper}).
 */
enum EmploymentStatus: string
{
    /** Employed and working. */
    case Active = 'active';

    /** Hired, not started yet. Access is granted from the start date, not the offer. */
    case PreHire = 'pre_hire';

    /**
     * Employed but away — parental leave, sabbatical, long-term sick. Still employed, so the
     * account stays: deprovisioning somebody on leave locks them out of their payslips.
     */
    case OnLeave = 'on_leave';

    /** Left. The account is deactivated and its sessions revoked. */
    case Terminated = 'terminated';

    /** Inactive for a reason the HR system does not distinguish from leaving. */
    case Inactive = 'inactive';

    /** Whether a person in this state keeps a working account. */
    public function grantsAccess(): bool
    {
        return match ($this) {
            self::Active, self::OnLeave => true,
            self::PreHire, self::Terminated, self::Inactive => false,
        };
    }
}
