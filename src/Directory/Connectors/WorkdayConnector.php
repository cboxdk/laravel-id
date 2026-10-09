<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Connectors;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\IncompleteHrisCredentials;
use Cbox\Id\Directory\Hris\Enums\EmploymentStatus;
use Cbox\Id\Directory\Hris\HrisConnector;
use Cbox\Id\Directory\Hris\Support\HrisValues;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;
use Cbox\Id\Directory\Support\JsonObjectList;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;

/**
 * Pulls workers from Workday through a Report-as-a-Service (RaaS) custom report.
 *
 * Workday has no fixed "list employees" endpoint a customer can point us at with the data
 * we need — its REST `workers` resource leaves out terminated workers, which is exactly
 * who a directory sync must see. What every Workday customer CAN do is build an advanced
 * custom report over "All Workers", enable it as a web service, and share it with an
 * Integration System User (ISU). We fetch that report as JSON:
 * `GET https://{host}/ccx/service/customreport2/{tenant}/{owner}/{report}?format=json`,
 * whose body is `{"Report_Entry": [ … ]}`, one object per worker, keyed by the column
 * aliases the report's author chose.
 *
 * **The aliases are a contract**: {@see self::COLUMNS} are the names the setup guide tells
 * the customer to give their columns, and a directory's `field_map` renames any of them for
 * a report that already exists. Only `Employee_ID` and `Work_Email` are indispensable.
 *
 * **Credentials** (`report_url` plus ONE of):
 * - an ISU's `username` (`ISU_name@tenant`) and `password`, sent as HTTP Basic; or
 * - an API client's `client_id`, `client_secret` and a non-expiring `refresh_token`,
 *   exchanged at `https://{host}/ccx/oauth2/{tenant}/token` for a bearer token.
 *
 * **The report address is the customer's, and the credentials go wherever it points**, so
 * it is pinned: HTTPS, a host under `cbox-id.directory.hris.workday_hosts` (Workday's own
 * `.workday.com` / `.myworkday.com`), and a `customreport2` path. Anything else is refused
 * before a request is made.
 *
 * No pagination (a RaaS report answers whole) and no incremental mode: every run is full.
 * Departments are the workers' supervisory organizations.
 */
class WorkdayConnector extends HrisConnector
{
    private const string REPORT_PATH = '/ccx/service/customreport2/';

    /** Our field => the report column alias the setup guide asks for. */
    public const array COLUMNS = [
        'id' => 'Employee_ID',
        'email' => 'Work_Email',
        'first_name' => 'Legal_First_Name',
        'last_name' => 'Legal_Last_Name',
        'display_name' => 'Preferred_Name',
        'active' => 'Active_Status',
        'on_leave' => 'On_Leave',
        'hire_date' => 'Hire_Date',
        'termination_date' => 'Termination_Date',
        'department_id' => 'Supervisory_Organization_ID',
        'department' => 'Supervisory_Organization',
        'manager_id' => 'Manager_Employee_ID',
        'title' => 'Business_Title',
    ];

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::Workday;
    }

    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable
    {
        $columns = [...self::COLUMNS, ...array_intersect_key($options->fieldMap, self::COLUMNS)];

        foreach ($this->report($credentials) as $row) {
            $employee = $this->employee($row, $columns, $options->customAttributes);

            if ($employee !== null) {
                yield $employee;
            }
        }
    }

    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable
    {
        // The supervisory organizations arrive on each worker; the sync files them.
        return [];
    }

    public function probe(array $credentials): void
    {
        // A RaaS report has no "first page": the cheapest honest probe is the report itself.
        iterator_to_array($this->report($credentials), false);
    }

    /**
     * The report's address, validated, with `format=json` forced; the tenant is the path
     * segment after `customreport2`.
     *
     * @return array{url: string, host: string, tenant: string}
     *
     * @throws IncompleteHrisCredentials
     */
    public static function reportAddress(string $url): array
    {
        $parts = parse_url(trim($url));
        $host = is_array($parts) ? strtolower((string) ($parts['host'] ?? '')) : '';
        $path = is_array($parts) ? (string) ($parts['path'] ?? '') : '';

        if (! is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || isset($parts['user']) || isset($parts['port'])) {
            throw IncompleteHrisCredentials::invalid('Workday', 'report_url', 'The report URL must be an https:// address with no port or credentials in it.');
        }

        $suffixes = config('cbox-id.directory.hris.workday_hosts', ['.workday.com', '.myworkday.com']);
        $allowed = false;

        foreach (is_array($suffixes) ? $suffixes : [] as $suffix) {
            if (is_string($suffix) && $suffix !== '' && str_ends_with($host, strtolower($suffix))) {
                $allowed = true;
            }
        }

        if (! $allowed) {
            throw IncompleteHrisCredentials::invalid('Workday', 'report_url', 'The report URL must be on your Workday host (…workday.com or …myworkday.com).');
        }

        $segments = explode('/', trim(substr($path, strlen(self::REPORT_PATH) - 1), '/'));

        if (! str_starts_with($path, self::REPORT_PATH) || count($segments) < 3 || in_array('', $segments, true) || in_array('..', $segments, true)) {
            throw IncompleteHrisCredentials::invalid('Workday', 'report_url', 'The report URL must be the report\'s web-service address: …/ccx/service/customreport2/{tenant}/{owner}/{report}.');
        }

        parse_str((string) ($parts['query'] ?? ''), $query);
        $query['format'] = 'json';

        return [
            'url' => 'https://'.$host.$path.'?'.http_build_query($query),
            'host' => $host,
            'tenant' => $segments[0],
        ];
    }

    /**
     * @param  array<string, mixed>  $credentials
     * @return iterable<array<string, mixed>>
     */
    private function report(array $credentials): iterable
    {
        try {
            $address = self::reportAddress($this->credential($credentials, 'report_url'));
        } catch (IncompleteHrisCredentials $e) {
            throw $this->failure($e->getMessage());
        }

        $request = $this->authorized($credentials, $address);

        $response = $this->http()->send(fn () => $request()->acceptJson()->get($address['url']), 'The report request');

        $body = $response->json();

        if (! is_array($body) || ! array_key_exists('Report_Entry', $body)) {
            throw $this->failure('The report did not answer as a JSON report (no Report_Entry) — check that it is enabled as a web service.');
        }

        return JsonObjectList::from($body['Report_Entry']);
    }

    /**
     * A request factory carrying the right authorization for the credentials given.
     *
     * @param  array<string, mixed>  $credentials
     * @param  array{url: string, host: string, tenant: string}  $address
     * @return \Closure(): PendingRequest
     */
    private function authorized(array $credentials, array $address): \Closure
    {
        // Any part of an API client means the API client: half of one is a mistake to
        // name, not a reason to fall back to a user name nobody gave.
        $oauth = $this->optional($credentials, 'refresh_token') !== null
            || $this->optional($credentials, 'client_id') !== null
            || $this->optional($credentials, 'client_secret') !== null;

        if ($oauth) {
            $clientId = $this->credential($credentials, 'client_id');
            $secret = $this->credential($credentials, 'client_secret');
            $refresh = $this->credential($credentials, 'refresh_token');

            $response = $this->http()->send(
                fn () => Http::asForm()->withBasicAuth($clientId, $secret)->post(
                    'https://'.$address['host'].'/ccx/oauth2/'.rawurlencode($address['tenant']).'/token',
                    ['grant_type' => 'refresh_token', 'refresh_token' => $refresh],
                ),
                'The token request',
            );

            $token = $response->json('access_token');

            if (! is_string($token) || $token === '') {
                throw $this->failure('Could not obtain an access token.');
            }

            return static fn () => Http::withToken($token);
        }

        $username = $this->credential($credentials, 'username');
        $password = $this->credential($credentials, 'password');

        return static fn () => Http::withBasicAuth($username, $password);
    }

    /**
     * @param  array<string, mixed>  $row
     * @param  array<string, string>  $columns
     * @param  list<string>  $custom
     */
    private function employee(array $row, array $columns, array $custom): ?HrisEmployee
    {
        $id = HrisValues::string($row, $columns['id']);

        if ($id === null) {
            return null;
        }

        $terminated = HrisValues::date($row, $columns['termination_date']);
        $active = HrisValues::bool($row, $columns['active']);

        $status = match (true) {
            $active === false => $terminated !== null ? EmploymentStatus::Terminated : EmploymentStatus::Inactive,
            HrisValues::bool($row, $columns['on_leave']) === true => EmploymentStatus::OnLeave,
            default => EmploymentStatus::Active,
        };

        return new HrisEmployee(
            id: $id,
            email: HrisValues::string($row, $columns['email']),
            status: $status,
            firstName: HrisValues::string($row, $columns['first_name']),
            lastName: HrisValues::string($row, $columns['last_name']),
            displayName: HrisValues::string($row, $columns['display_name']),
            startDate: HrisValues::date($row, $columns['hire_date']),
            terminationDate: $terminated,
            departmentId: HrisValues::string($row, $columns['department_id']),
            departmentName: HrisValues::string($row, $columns['department']),
            managerId: HrisValues::string($row, $columns['manager_id']),
            jobTitle: HrisValues::string($row, $columns['title']),
            employeeNumber: $id,
            customAttributes: HrisValues::custom($row, $custom),
        );
    }
}
