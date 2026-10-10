<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Connectors;

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\IncompleteHrisCredentials;
use Cbox\Id\Directory\Hris\Enums\EmploymentStatus;
use Cbox\Id\Directory\Hris\HrisConnector;
use Cbox\Id\Directory\Hris\Support\HrisValues;
use Cbox\Id\Directory\Hris\ValueObjects\HrisDepartment;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;
use Cbox\Id\Directory\Support\JsonObjectList;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;

/**
 * Pulls employees from BambooHR's REST API.
 *
 * - **Auth**: an API key as the HTTP Basic username (the password is ignored; we send `x`).
 *   The key carries its owner's access level, so the setup guide asks for a dedicated user
 *   whose access level sees every employee, active and inactive.
 * - **Base**: `https://{subdomain}.bamboohr.com/api/v1`. The subdomain is validated to a
 *   bare DNS label before anything is sent, so the key can only go to BambooHR.
 * - **Employees**: `GET /employees` with the fields we read, cursor-paged
 *   (`page[limit]`, `page[after]` ← `meta.page.nextCursor`). Asked twice — once with
 *   `filter[status]=active`, once with `inactive` — because whether the unfiltered list
 *   includes inactive people is not something the documentation promises, and a leaver
 *   we never see is a leaver we never deprovision.
 * - **Departments**: `GET /meta/lists`, the list whose alias is `department`; its option
 *   ids are what an employee's `departmentId` holds.
 * - **Incremental**: `GET /employees/changed?since=…&type=all` names who changed; those
 *   are re-read by id (`filter[ids]`), and a `Deleted` one arrives as terminated with no
 *   email, which deactivates them if we had them.
 * - **Rate limits**: BambooHR answers `503` (historically) or `429` with `Retry-After`;
 *   both are retried by the shared client.
 */
class BambooHrConnector extends HrisConnector
{
    private const array FIELDS = [
        'firstName', 'lastName', 'preferredName', 'displayName', 'workEmail', 'status',
        'hireDate', 'terminationDate', 'departmentId', 'departmentName', 'reportsToId',
        'employeeNumber', 'jobTitleName',
    ];

    private const int PAGE = 500;

    private const int IDS_PER_REQUEST = 100;

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::BambooHr;
    }

    public function supportsIncremental(): bool
    {
        return true;
    }

    /**
     * The bare company subdomain, from whatever was pasted: `acme`, `acme.bamboohr.com`,
     * or `https://acme.bamboohr.com/home`.
     *
     * @throws IncompleteHrisCredentials
     */
    public static function subdomain(string $given): string
    {
        $value = strtolower(trim($given));
        $value = (string) preg_replace('#^https?://#', '', $value);
        $value = explode('/', $value)[0];
        $value = (string) preg_replace('/\.bamboohr\.com$/', '', $value);

        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $value) !== 1) {
            throw IncompleteHrisCredentials::invalid('BambooHR', 'subdomain', 'The company subdomain is the part before .bamboohr.com in your BambooHR address.');
        }

        return $value;
    }

    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable
    {
        $base = $this->base($credentials);
        $client = $this->client($credentials);
        $fields = implode(',', array_values(array_unique([...self::FIELDS, ...$options->customAttributes])));

        if ($options->changedSince !== null) {
            yield from $this->changed($base, $client, $fields, $options);

            return;
        }

        foreach (['active', 'inactive'] as $status) {
            yield from $this->pages($base, $client, ['fields' => $fields, 'filter[status]' => $status], $options);
        }
    }

    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable
    {
        $base = $this->base($credentials);
        $client = $this->client($credentials);

        $response = $this->http()->send(fn () => $client()->get($base.'/meta/lists'), 'The department list request');

        foreach (JsonObjectList::from($response->json()) as $list) {
            if (HrisValues::string($list, 'alias') !== 'department') {
                continue;
            }

            foreach (JsonObjectList::from($list['options'] ?? null) as $option) {
                $id = HrisValues::string($option, 'id');
                $name = HrisValues::string($option, 'name');

                if ($id !== null && $name !== null && HrisValues::string($option, 'archived') !== 'yes') {
                    yield new HrisDepartment($id, $name);
                }
            }
        }
    }

    public function probe(array $credentials): void
    {
        $base = $this->base($credentials);
        $client = $this->client($credentials);

        $this->http()->send(fn () => $client()->get($base.'/employees', ['fields' => 'workEmail', 'page[limit]' => 1]), 'The employee list request');
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    private function base(array $credentials): string
    {
        try {
            $subdomain = self::subdomain($this->credential($credentials, 'subdomain'));
        } catch (IncompleteHrisCredentials $e) {
            throw $this->failure($e->getMessage());
        }

        return 'https://'.$subdomain.'.bamboohr.com/api/v1';
    }

    /**
     * @param  array<string, mixed>  $credentials
     * @return \Closure(): PendingRequest
     */
    private function client(array $credentials): \Closure
    {
        $key = $this->credential($credentials, 'api_key');

        return static fn (): PendingRequest => Http::withBasicAuth($key, 'x')->acceptJson();
    }

    /**
     * @param  \Closure(): PendingRequest  $client
     * @param  array<string, string|int>  $query
     * @return iterable<HrisEmployee>
     */
    private function pages(string $base, \Closure $client, array $query, HrisSyncOptions $options): iterable
    {
        $after = null;

        do {
            $page = [...$query, 'page[limit]' => self::PAGE, ...($after === null ? [] : ['page[after]' => $after])];
            $response = $this->http()->send(fn () => $client()->get($base.'/employees', $page), 'The employee list request');

            foreach (JsonObjectList::from($response->json('data')) as $row) {
                $employee = $this->employee($row, $options->customAttributes);

                if ($employee !== null) {
                    yield $employee;
                }
            }

            $after = HrisValues::stringOf($response->json('meta.page.nextCursor'));
        } while ($after !== null);
    }

    /**
     * @param  \Closure(): PendingRequest  $client
     * @return iterable<HrisEmployee>
     */
    private function changed(string $base, \Closure $client, string $fields, HrisSyncOptions $options): iterable
    {
        /** @var CarbonImmutable $since */
        $since = $options->changedSince;

        $response = $this->http()->send(
            fn () => $client()->get($base.'/employees/changed', ['since' => $since->toIso8601String(), 'type' => 'all']),
            'The changed-employees request',
        );

        $changed = $response->json('employees');
        $ids = [];

        foreach (is_array($changed) ? $changed : [] as $key => $entry) {
            $id = is_array($entry) ? (HrisValues::string($entry, 'id') ?? HrisValues::stringOf($key)) : HrisValues::stringOf($key);

            if ($id === null) {
                continue;
            }

            if (is_array($entry) && strtolower((string) HrisValues::string($entry, 'action')) === 'deleted') {
                // Gone from BambooHR altogether: nothing to read, somebody to deactivate.
                yield new HrisEmployee(id: $id, email: null, status: EmploymentStatus::Terminated);

                continue;
            }

            $ids[] = $id;
        }

        foreach (array_chunk($ids, self::IDS_PER_REQUEST) as $chunk) {
            yield from $this->pages($base, $client, ['fields' => $fields, 'filter[ids]' => implode(',', $chunk)], $options);
        }
    }

    /**
     * @param  array<string, mixed>  $row
     * @param  list<string>  $custom
     */
    private function employee(array $row, array $custom): ?HrisEmployee
    {
        $id = HrisValues::string($row, 'employeeId') ?? HrisValues::string($row, 'id');

        if ($id === null) {
            return null;
        }

        $terminated = HrisValues::date($row, 'terminationDate');
        $status = match (strtolower((string) HrisValues::string($row, 'status'))) {
            'inactive' => $terminated !== null ? EmploymentStatus::Terminated : EmploymentStatus::Inactive,
            default => EmploymentStatus::Active,
        };

        $preferred = HrisValues::string($row, 'preferredName');
        $first = HrisValues::string($row, 'firstName');

        return new HrisEmployee(
            id: $id,
            email: HrisValues::string($row, 'workEmail'),
            status: $status,
            firstName: $first,
            lastName: HrisValues::string($row, 'lastName'),
            displayName: HrisValues::string($row, 'displayName') ?? ($preferred === null ? null : trim($preferred.' '.HrisValues::string($row, 'lastName'))),
            startDate: HrisValues::date($row, 'hireDate'),
            terminationDate: $terminated,
            departmentId: HrisValues::string($row, 'departmentId'),
            departmentName: HrisValues::string($row, 'departmentName'),
            managerId: HrisValues::string($row, 'reportsToId'),
            jobTitle: HrisValues::string($row, 'jobTitleName'),
            employeeNumber: HrisValues::string($row, 'employeeNumber'),
            customAttributes: HrisValues::custom($row, $custom),
        );
    }
}
