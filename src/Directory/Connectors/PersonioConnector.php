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
 * Pulls people from Personio's v2 API (`https://api.personio.de/v2`).
 *
 * - **Auth**: API credentials (client id + secret) exchanged at `POST /v2/auth/token`
 *   (`client_credentials`, form-encoded) for a bearer token, once per run. The credentials
 *   need the `personio:persons:read` and `personio:org-units:read` scopes.
 * - **People**: `GET /v2/persons?limit=50`, cursor-paged through `_meta.links.next.href`
 *   (a URL from the response body, so pinned to Personio's host). The employment — status,
 *   start and termination dates, supervisor, department, title — is a separate resource,
 *   `GET /v2/persons/{id}/employments`, one request per person: Personio has no bulk read.
 *   Of several employments the current one is taken (active, onboarding or on leave first,
 *   then the latest start).
 * - **Status**: `ONBOARDING` is a pre-hire, `LEAVE` on leave, `INACTIVE` inactive (or
 *   terminated, with a termination date).
 * - **Departments**: `GET /v2/org-units?type=department`; an employment's org units of type
 *   `department` name the one a person is filed under.
 * - **No incremental mode**, on purpose: `updated_at.gt` filters PERSONS, and a termination
 *   is recorded on the EMPLOYMENT, which the documentation does not promise moves the
 *   person's timestamp. A leaver missed by an incremental run would keep access until the
 *   next full one; every run is full instead.
 * - **Rate limits**: 429s, with no documented header; the shared client backs off.
 */
class PersonioConnector extends HrisConnector
{
    private const string BASE = 'https://api.personio.de/v2';

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::Personio;
    }

    public function fetchEmployees(array $credentials, HrisSyncOptions $options): iterable
    {
        $client = $this->client($credentials);

        foreach ($this->collection($client, '/persons', ['limit' => 50], 'The persons request') as $person) {
            $id = HrisValues::string($person, 'id');

            if ($id === null) {
                continue;
            }

            $employments = iterator_to_array(
                $this->collection($client, '/persons/'.rawurlencode($id).'/employments', ['limit' => 50], 'The employments request'),
                false,
            );

            yield $this->employee($id, $person, self::current($employments), $options->customAttributes);
        }
    }

    public function fetchDepartments(array $credentials, HrisSyncOptions $options): iterable
    {
        $client = $this->client($credentials);

        foreach ($this->collection($client, '/org-units', ['type' => 'department', 'limit' => 100], 'The org-units request') as $unit) {
            $id = HrisValues::string($unit, 'id');
            $name = HrisValues::string($unit, 'name');

            if ($id !== null && $name !== null) {
                yield new HrisDepartment($id, $name, HrisValues::string($unit, 'parent_id'));
            }
        }
    }

    public function probe(array $credentials): void
    {
        $client = $this->client($credentials);

        $this->http()->send(fn () => $client()->get(self::BASE.'/persons', ['limit' => 1]), 'The persons request');
    }

    /**
     * A request factory with a bearer token minted for this run.
     *
     * @param  array<string, mixed>  $credentials
     * @return \Closure(): PendingRequest
     */
    private function client(array $credentials): \Closure
    {
        $clientId = $this->credential($credentials, 'client_id');
        $secret = $this->credential($credentials, 'client_secret');

        $response = $this->http()->send(fn () => Http::asForm()->acceptJson()->post(self::BASE.'/auth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $secret,
        ]), 'The token request');

        $token = $response->json('access_token');

        if (! is_string($token) || $token === '') {
            throw $this->failure('Could not obtain an access token.');
        }

        return static fn (): PendingRequest => Http::withToken($token)->acceptJson();
    }

    /**
     * @param  \Closure(): PendingRequest  $client
     * @param  array<string, string|int>  $query
     * @return iterable<array<string, mixed>>
     */
    private function collection(\Closure $client, string $path, array $query, string $what): iterable
    {
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

            yield from JsonObjectList::from($response->json('_data'));

            $url = $this->pinned($response->json('_meta.links.next.href'), self::BASE);
            $params = [];
        }
    }

    /**
     * The employment that describes the person now.
     *
     * @param  list<array<string, mixed>>  $employments
     * @return array<string, mixed>
     */
    private static function current(array $employments): array
    {
        usort($employments, static function (array $a, array $b): int {
            $rank = static fn (array $e): int => in_array(strtoupper((string) HrisValues::string($e, 'status')), ['ACTIVE', 'LEAVE', 'ONBOARDING'], true) ? 1 : 0;

            return [$rank($b), (string) HrisValues::string($b, 'employment_start_date')] <=> [$rank($a), (string) HrisValues::string($a, 'employment_start_date')];
        });

        return $employments[0] ?? [];
    }

    /**
     * @param  array<string, mixed>  $person
     * @param  array<string, mixed>  $employment
     * @param  list<string>  $custom
     */
    private function employee(string $id, array $person, array $employment, array $custom): HrisEmployee
    {
        $terminated = HrisValues::date($employment, 'termination', 'termination_date')
            ?? HrisValues::date($employment, 'termination', 'last_working_day');

        $status = match (strtoupper((string) (HrisValues::string($employment, 'status') ?? HrisValues::string($person, 'status')))) {
            'ONBOARDING' => EmploymentStatus::PreHire,
            'LEAVE' => EmploymentStatus::OnLeave,
            'INACTIVE' => $terminated !== null ? EmploymentStatus::Terminated : EmploymentStatus::Inactive,
            default => EmploymentStatus::Active,
        };

        $department = null;

        foreach (JsonObjectList::from($employment['org_units'] ?? null) as $unit) {
            if (HrisValues::string($unit, 'type') === 'department') {
                $department = HrisValues::string($unit, 'id');
            }
        }

        $preferred = HrisValues::string($person, 'preferred_name');

        return new HrisEmployee(
            id: $id,
            email: HrisValues::string($person, 'email'),
            status: $status,
            firstName: HrisValues::string($person, 'first_name'),
            lastName: HrisValues::string($person, 'last_name'),
            displayName: $preferred,
            startDate: HrisValues::date($employment, 'employment_start_date'),
            terminationDate: $terminated,
            departmentId: $department,
            managerId: HrisValues::string($employment, 'supervisor', 'id'),
            jobTitle: HrisValues::string($employment, 'position', 'title'),
            customAttributes: self::customAttributes($person, $custom),
        );
    }

    /**
     * Personio's custom attributes are a list of `{id, global_id, label, value}`; a requested
     * name matches any of the three identifiers.
     *
     * @param  array<string, mixed>  $person
     * @param  list<string>  $names
     * @return array<string, scalar|null>
     */
    private static function customAttributes(array $person, array $names): array
    {
        $out = [];
        $attributes = JsonObjectList::from($person['custom_attributes'] ?? null);

        foreach ($names as $name) {
            $out[$name] = null;

            foreach ($attributes as $attribute) {
                if (in_array($name, [HrisValues::string($attribute, 'id'), HrisValues::string($attribute, 'global_id'), HrisValues::string($attribute, 'label')], true)) {
                    $out[$name] = HrisValues::scalar($attribute['value'] ?? null);
                }
            }
        }

        return $out;
    }
}
