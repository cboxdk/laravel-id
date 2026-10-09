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
 * Pulls workers from Rippling's REST API (`https://rest.ripplingapis.com`).
 *
 * - **Auth**: a customer-created API token as a bearer token, with the `workers.read`,
 *   `users.read` and `departments.read` scopes. The token inherits its creator's
 *   permission profile, so the guide asks for a profile that covers the entire company —
 *   otherwise we see the creator's reports and nobody else, and the deprovisioning guard
 *   is what stands between that and a mass deactivation.
 * - **Workers**: `GET /workers/?limit=100&expand=user,department`, terminated workers
 *   included; followed through `next_link`, which is a full URL taken from the response
 *   body and therefore pinned to the API's own host.
 * - **Status**: `INIT`, `HIRED`, `ACCEPTED` are pre-hires; `ACTIVE`; `TERMINATED`, with
 *   `end_date` as the termination date. `manager_id` is a worker id.
 * - **Incremental**: `filter=updated_at ge {timestamp}`.
 * - **Rate limits**: 429 under Cloudflare's sliding window; retried with Retry-After.
 */
class RipplingConnector extends HrisConnector
{
    private const string BASE = 'https://rest.ripplingapis.com';

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::Rippling;
    }

    public function supportsIncremental(): bool
    {
        return true;
    }

    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable
    {
        $query = ['limit' => 100, 'expand' => 'user,department'];

        if ($options->changedSince !== null) {
            $query['filter'] = 'updated_at ge '.$options->changedSince->utc()->format('Y-m-d\TH:i:s');
            $query['order_by'] = 'updated_at';
        }

        foreach ($this->collection($credentials, '/workers/', $query, 'The workers request') as $worker) {
            $employee = $this->employee($worker, $options->customAttributes);

            if ($employee !== null) {
                yield $employee;
            }
        }
    }

    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable
    {
        foreach ($this->collection($credentials, '/departments/', ['limit' => 100], 'The departments request') as $department) {
            $id = HrisValues::string($department, 'id');
            $name = HrisValues::string($department, 'name');

            if ($id !== null && $name !== null) {
                yield new HrisDepartment($id, $name, HrisValues::string($department, 'parent_id'));
            }
        }
    }

    public function probe(array $credentials): void
    {
        $client = $this->client($credentials);

        $this->http()->send(fn () => $client()->get(self::BASE.'/workers/', ['limit' => 1]), 'The workers request');
    }

    /**
     * Every object of a cursor-paged collection.
     *
     * @param  array<string, mixed>  $credentials
     * @param  array<string, string|int>  $query
     * @return iterable<array<string, mixed>>
     */
    private function collection(array $credentials, string $path, array $query, string $what): iterable
    {
        $client = $this->client($credentials);
        $url = self::BASE.$path;
        $params = $query;

        while ($url !== null) {
            $current = $url;
            $currentParams = $params;
            // A continuation link carries its own query; handing Guzzle an empty `query`
            // option would REPLACE it and fetch the first page forever.
            $response = $this->http()->send(
                fn () => $currentParams === [] ? $client()->get($current) : $client()->get($current, $currentParams),
                $what,
            );

            yield from JsonObjectList::from($response->json('results'));

            // `next_link` already carries the query; follow it as-is, on this host only.
            $url = $this->pinned($response->json('next_link'), self::BASE);
            $params = [];
        }
    }

    /**
     * @param  array<string, mixed>  $credentials
     * @return \Closure(): PendingRequest
     */
    private function client(array $credentials): \Closure
    {
        $token = $this->credential($credentials, 'api_token');

        return static fn (): PendingRequest => Http::withToken($token)->acceptJson();
    }

    /**
     * @param  array<string, mixed>  $worker
     * @param  list<string>  $custom
     */
    private function employee(array $worker, array $custom): ?HrisEmployee
    {
        $id = HrisValues::string($worker, 'id');

        if ($id === null) {
            return null;
        }

        $status = match (strtoupper((string) HrisValues::string($worker, 'status'))) {
            'INIT', 'HIRED', 'ACCEPTED' => EmploymentStatus::PreHire,
            'TERMINATED' => EmploymentStatus::Terminated,
            default => EmploymentStatus::Active,
        };

        return new HrisEmployee(
            id: $id,
            email: HrisValues::string($worker, 'work_email'),
            status: $status,
            firstName: HrisValues::string($worker, 'user', 'name', 'given_name'),
            lastName: HrisValues::string($worker, 'user', 'name', 'family_name'),
            displayName: HrisValues::string($worker, 'user', 'display_name'),
            startDate: HrisValues::date($worker, 'start_date'),
            terminationDate: HrisValues::date($worker, 'end_date'),
            departmentId: HrisValues::string($worker, 'department_id') ?? HrisValues::string($worker, 'department', 'id'),
            departmentName: HrisValues::string($worker, 'department', 'name'),
            managerId: HrisValues::string($worker, 'manager_id'),
            jobTitle: HrisValues::string($worker, 'title'),
            employeeNumber: HrisValues::string($worker, 'user', 'number') ?? HrisValues::string($worker, 'number'),
            customAttributes: HrisValues::custom($worker, $custom, static fn (array $record, string $name): mixed => HrisValues::at($record, ...explode('.', $name))),
        );
    }
}
