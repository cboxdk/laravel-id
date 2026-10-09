<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Connectors;

use Cbox\Id\Directory\Enums\DirectoryProvider;
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
 * Pulls people from HiBob (Bob) through its public API (`https://api.hibob.com/v1`).
 *
 * - **Auth**: an API service user — its id and token as HTTP Basic. The service user's
 *   permission group must read the root, work and lifecycle field categories, and must NOT
 *   be limited to employed people; otherwise `showInactive` returns nobody extra and
 *   leavers are never seen.
 * - **People**: `POST /people/search` with the fields we read and `showInactive: true`.
 *   One answer, no paging. Bob may answer a field nested (`work.department`) or flat
 *   (`/work/department` → `{value}`); both are read.
 * - **Status**: `internal.lifecycleStatus` — `hired` is a pre-hire, `employed` active, any
 *   leave on leave, `terminated` terminated. `garden leave` is a notice period spent away
 *   from work and is treated as INACTIVE: the person is still paid, but their access ends.
 * - **Departments**: `work.department` holds a named-list item id (machine format), named by
 *   `GET /company/named-lists/department`, whose items may nest.
 * - **No incremental mode**: Bob offers webhooks, not "changed since".
 * - **Rate limits**: `people/search` allows 50 a minute; 429 carries `X-RateLimit-Reset`.
 *   Bob blocks an address that keeps sending refused credentials, so a 401 is final at once.
 */
class HiBobConnector extends HrisConnector
{
    private const string BASE = 'https://api.hibob.com/v1';

    private const array FIELDS = [
        'root.id', 'root.email', 'root.firstName', 'root.surname', 'root.displayName',
        'internal.status', 'internal.lifecycleStatus', 'internal.terminationDate',
        'work.startDate', 'work.department', 'work.reportsTo', 'work.manager', 'work.title',
        'work.employeeIdInCompany',
    ];

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::HiBob;
    }

    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable
    {
        $client = $this->client($credentials);
        $fields = array_values(array_unique([...self::FIELDS, ...$options->customAttributes]));

        $response = $this->http()->send(fn () => $client()->post(self::BASE.'/people/search', [
            'fields' => $fields,
            'showInactive' => true,
            'humanReadable' => '',
        ]), 'The people search');

        foreach (JsonObjectList::from($response->json('employees')) as $person) {
            $employee = $this->employee($person, $options->customAttributes);

            if ($employee !== null) {
                yield $employee;
            }
        }
    }

    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable
    {
        $client = $this->client($credentials);

        $response = $this->http()->send(fn () => $client()->get(self::BASE.'/company/named-lists/department'), 'The department list request');

        yield from $this->items(JsonObjectList::from($response->json('items')), null);
    }

    public function probe(array $credentials): void
    {
        $client = $this->client($credentials);

        $this->http()->send(fn () => $client()->get(self::BASE.'/company/named-lists/department'), 'The department list request');
    }

    /**
     * @param  list<array<string, mixed>>  $items
     * @return iterable<HrisDepartment>
     */
    private function items(array $items, ?string $parent): iterable
    {
        foreach ($items as $item) {
            $id = HrisValues::string($item, 'id');
            $name = HrisValues::string($item, 'name') ?? HrisValues::string($item, 'value');

            if ($id === null || $name === null) {
                continue;
            }

            if (HrisValues::bool($item, 'archived') !== true) {
                yield new HrisDepartment($id, $name, $parent);
            }

            yield from $this->items(JsonObjectList::from($item['children'] ?? null), $id);
        }
    }

    /**
     * @param  array<string, mixed>  $credentials
     * @return \Closure(): PendingRequest
     */
    private function client(array $credentials): \Closure
    {
        $id = $this->credential($credentials, 'service_user_id');
        $token = $this->credential($credentials, 'service_user_token');

        return static fn (): PendingRequest => Http::withBasicAuth($id, $token)->acceptJson();
    }

    /**
     * A field by its dotted id, nested or flat.
     *
     * @param  array<mixed>  $person
     */
    private static function field(array $person, string $field): mixed
    {
        $path = explode('.', $field);

        // `root.*` fields also arrive at the top level.
        $nested = HrisValues::at($person, ...$path) ?? ($path[0] === 'root' ? HrisValues::at($person, ...array_slice($path, 1)) : null);

        if ($nested !== null) {
            return $nested;
        }

        $flat = $person['/'.implode('/', $path)] ?? null;

        return is_array($flat) && array_key_exists('value', $flat) ? $flat['value'] : $flat;
    }

    /**
     * @param  array<string, mixed>  $person
     * @param  list<string>  $custom
     */
    private function employee(array $person, array $custom): ?HrisEmployee
    {
        $id = HrisValues::stringOf(self::field($person, 'root.id'));

        if ($id === null) {
            return null;
        }

        $terminated = HrisValues::dateOf(self::field($person, 'internal.terminationDate'));
        $lifecycle = strtolower((string) HrisValues::stringOf(self::field($person, 'internal.lifecycleStatus')));
        $active = strtolower((string) HrisValues::stringOf(self::field($person, 'internal.status')));

        $status = match (true) {
            $lifecycle === 'hired' => EmploymentStatus::PreHire,
            $lifecycle === 'terminated' => EmploymentStatus::Terminated,
            $lifecycle === 'garden leave' => EmploymentStatus::Inactive,
            str_contains($lifecycle, 'leave') => EmploymentStatus::OnLeave,
            $lifecycle === 'employed' => EmploymentStatus::Active,
            $active === 'inactive' => $terminated !== null ? EmploymentStatus::Terminated : EmploymentStatus::Inactive,
            default => EmploymentStatus::Active,
        };

        $reportsTo = self::field($person, 'work.reportsTo');
        $manager = is_array($reportsTo) ? HrisValues::string($reportsTo, 'id') : null;

        return new HrisEmployee(
            id: $id,
            email: HrisValues::stringOf(self::field($person, 'root.email')),
            status: $status,
            firstName: HrisValues::stringOf(self::field($person, 'root.firstName')),
            lastName: HrisValues::stringOf(self::field($person, 'root.surname')),
            displayName: HrisValues::stringOf(self::field($person, 'root.displayName')),
            startDate: HrisValues::dateOf(self::field($person, 'work.startDate')),
            terminationDate: $terminated,
            departmentId: HrisValues::stringOf(self::field($person, 'work.department')),
            managerId: $manager ?? HrisValues::stringOf(self::field($person, 'work.manager')),
            jobTitle: HrisValues::stringOf(self::field($person, 'work.title')),
            employeeNumber: HrisValues::stringOf(self::field($person, 'work.employeeIdInCompany')),
            customAttributes: HrisValues::custom($person, $custom, static fn (array $record, string $name): mixed => self::field($record, $name)),
        );
    }
}
