<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\Contracts;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Hris\HrisDirectorySync;
use Cbox\Id\Directory\Hris\ValueObjects\HrisDepartment;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;

/**
 * An HR system we pull employees from (Workday, BambooHR, Rippling, HiBob, Personio).
 *
 * A {@see DirectoryConnector} first — so the registry, the scheduled command and the
 * reconciliation that already handle Google Workspace and Microsoft Entra handle these
 * without a second code path for "is it a directory" — with the richer employment record
 * on top. {@see DirectoryPullSync} notices this contract and runs the
 * HR-aware sync ({@see HrisDirectorySync}): start and termination
 * dates decide access, departments become groups, the manager becomes an attribute, and a
 * partial failure is reported instead of aborting the run.
 *
 * Implementations page transparently, back off on rate limits (429 / Retry-After), pin
 * every continuation URL they read out of a response body to the provider's own host, and
 * never include a credential in an exception message.
 */
interface HrisProvider extends DirectoryConnector
{
    /**
     * Employees — including terminated ones the provider still reports, which is how a
     * leaver is told apart from a record the API simply did not return.
     *
     * @param  array<string, mixed>  $credentials
     * @return iterable<HrisEmployee>
     *
     * @throws DirectoryConnectionFailed
     */
    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable;

    /**
     * The departments. A provider that only knows a department as a field on the employee
     * yields nothing; the sync then builds the groups from the employees' own department.
     *
     * @param  array<string, mixed>  $credentials
     * @return iterable<HrisDepartment>
     *
     * @throws DirectoryConnectionFailed
     */
    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable;

    /** Whether {@see HrisSyncOptions::$changedSince} is honoured by the provider's API. */
    public function supportsIncremental(): bool;

    /**
     * {@see DirectoryConnector::verify()} with the reason: a cheap probe that throws the
     * provider's refusal in words an administrator can act on ("the credentials lack
     * permission to read employees") instead of a bare false.
     *
     * @param  array<string, mixed>  $credentials
     *
     * @throws DirectoryConnectionFailed
     */
    public function probe(array $credentials): void;
}
