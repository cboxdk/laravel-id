<?php

declare(strict_types=1);

use Cbox\Id\Directory\Connectors\BambooHrConnector;
use Cbox\Id\Directory\Connectors\HiBobConnector;
use Cbox\Id\Directory\Connectors\PersonioConnector;
use Cbox\Id\Directory\Connectors\RipplingConnector;
use Cbox\Id\Directory\Connectors\WorkdayConnector;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Hris\Enums\EmploymentStatus;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;

/**
 * Each HR system's documented API, replayed with Http::fake: the paging scheme, terminated
 * people arriving as terminated, the manager arriving as the manager's own employee id,
 * departments, and a 429 retried rather than ending the run.
 *
 * The fixtures follow the vendors' published field names and example bodies.
 */
beforeEach(function (): void {
    Sleep::fake();
});

/**
 * @param  iterable<HrisEmployee>  $employees
 * @return array<string, HrisEmployee>
 */
function hrisById(iterable $employees): array
{
    $out = [];

    foreach ($employees as $employee) {
        $out[$employee->id] = $employee;
    }

    return $out;
}

it('reads a Workday RaaS report with an integration user, terminated workers included', function (): void {
    Http::fake([
        'wd5-services1.myworkday.com/ccx/service/customreport2/*' => Http::response(['Report_Entry' => [
            ['Employee_ID' => '21001', 'Work_Email' => 'lmcneil@acme.com', 'Legal_First_Name' => 'Logan', 'Legal_Last_Name' => 'McNeil', 'Preferred_Name' => 'Logan McNeil', 'Active_Status' => '1', 'Hire_Date' => '2015-01-05', 'Termination_Date' => '', 'Supervisory_Organization_ID' => 'SUP_ORG_HR', 'Supervisory_Organization' => 'Human Resources', 'Manager_Employee_ID' => '21000', 'Business_Title' => 'VP, HR', 'Location' => 'Copenhagen'],
            ['Employee_ID' => '21044', 'Work_Email' => 'aruiz@acme.com', 'Legal_First_Name' => 'Ana', 'Legal_Last_Name' => 'Ruiz', 'Active_Status' => '0', 'Hire_Date' => '2019-03-01', 'Termination_Date' => '2024-06-30', 'Supervisory_Organization_ID' => 'SUP_ORG_ENG', 'Supervisory_Organization' => 'Engineering', 'Manager_Employee_ID' => '21010'],
            ['Employee_ID' => '21050', 'Work_Email' => 'leave@acme.com', 'Active_Status' => '1', 'On_Leave' => '1'],
        ]]),
    ]);

    $employees = hrisById((new WorkdayConnector)->fetchEmployees([
        'report_url' => 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU_CboxID/Cbox_ID_Workers?format=csv',
        'username' => 'ISU_CboxID@acme',
        'password' => 'pw',
    ], new HrisSyncOptions(customAttributes: ['Location'])));

    expect($employees)->toHaveCount(3)
        ->and($employees['21001']->status)->toBe(EmploymentStatus::Active)
        ->and($employees['21001']->managerId)->toBe('21000')
        ->and($employees['21001']->departmentId)->toBe('SUP_ORG_HR')
        ->and($employees['21001']->departmentName)->toBe('Human Resources')
        ->and($employees['21001']->displayName)->toBe('Logan McNeil')
        ->and($employees['21001']->customAttributes)->toBe(['Location' => 'Copenhagen'])
        ->and($employees['21044']->status)->toBe(EmploymentStatus::Terminated)
        ->and($employees['21044']->terminationDate?->toDateString())->toBe('2024-06-30')
        ->and($employees['21050']->status)->toBe(EmploymentStatus::OnLeave);

    // The report is asked for as JSON whatever format the pasted address named, with Basic auth.
    Http::assertSent(fn (Request $request): bool => str_contains($request->url(), 'format=json')
        && ! str_contains($request->url(), 'format=csv')
        && $request->hasHeader('Authorization', 'Basic '.base64_encode('ISU_CboxID@acme:pw')));
});

it('reads a Workday report with an OAuth refresh token and renamed columns', function (): void {
    Http::fake([
        'wd2-impl-services1.workday.com/ccx/oauth2/acme_tenant/token' => Http::response(['access_token' => 'wd-access', 'token_type' => 'Bearer']),
        'wd2-impl-services1.workday.com/ccx/service/*' => Http::response(['Report_Entry' => [
            ['Worker' => 'W-1', 'Email' => 'a@acme.com', 'Active_Status' => '1'],
        ]]),
    ]);

    $employees = hrisById((new WorkdayConnector)->fetchEmployees([
        'report_url' => 'https://wd2-impl-services1.workday.com/ccx/service/customreport2/acme_tenant/owner/Workers',
        'client_id' => 'cid', 'client_secret' => 'csecret', 'refresh_token' => 'rt',
    ], new HrisSyncOptions(fieldMap: ['id' => 'Worker', 'email' => 'Email', 'not_a_field' => 'X'])));

    expect($employees)->toHaveKey('W-1')->and($employees['W-1']->email)->toBe('a@acme.com');

    Http::assertSent(fn (Request $request): bool => str_ends_with($request->url(), '/ccx/oauth2/acme_tenant/token')
        && $request['grant_type'] === 'refresh_token'
        && $request->hasHeader('Authorization', 'Basic '.base64_encode('cid:csecret')));
    Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/customreport2/')
        && $request->hasHeader('Authorization', 'Bearer wd-access'));
});

it('refuses a Workday report address that is not Workday\'s, before sending anything', function (string $url): void {
    Http::fake();

    expect(fn () => iterator_to_array((new WorkdayConnector)->fetchEmployees(
        ['report_url' => $url, 'username' => 'u@t', 'password' => 'p'],
        new HrisSyncOptions,
    )))->toThrow(DirectoryConnectionFailed::class);

    Http::assertNothingSent();
})->with([
    'another host' => ['https://attacker.test/ccx/service/customreport2/t/o/r'],
    'a lookalike host' => ['https://wd5-services1.myworkday.com.attacker.test/ccx/service/customreport2/t/o/r'],
    'plaintext' => ['http://wd5-services1.myworkday.com/ccx/service/customreport2/t/o/r'],
    'not a report' => ['https://wd5-services1.myworkday.com/ccx/api/v1/t/workers'],
    'credentials in the address' => ['https://u:p@wd5-services1.myworkday.com/ccx/service/customreport2/t/o/r'],
]);

it('pages BambooHR by cursor, asks for active and inactive, and maps departments from the list fields', function (): void {
    Http::fake([
        'acme.bamboohr.com/api/v1/employees?*filter%5Bstatus%5D=active*' => Http::sequence()
            ->push(['data' => [
                ['employeeId' => '123', 'firstName' => 'Ava', 'lastName' => 'Nguyen', 'jobTitleName' => 'Engineering Manager', 'status' => 'Active', 'workEmail' => 'ava@acme.com', 'displayName' => 'Ava Nguyen', 'hireDate' => '2021-04-12', 'terminationDate' => null, 'departmentId' => 45, 'departmentName' => 'Engineering', 'reportsToId' => '101', 'employeeNumber' => 'E-0123'],
            ], 'meta' => ['page' => ['nextCursor' => 'cur-2']]])
            ->push(['data' => [
                ['employeeId' => '124', 'firstName' => 'Cy', 'lastName' => 'Berg', 'status' => 'Active', 'workEmail' => 'cy@acme.com', 'hireDate' => '2022-01-01', 'terminationDate' => '0000-00-00', 'departmentId' => 45, 'departmentName' => 'Engineering', 'reportsToId' => '123'],
            ], 'meta' => ['page' => ['nextCursor' => null]]]),
        'acme.bamboohr.com/api/v1/employees?*filter%5Bstatus%5D=inactive*' => Http::response(['data' => [
            ['employeeId' => '140', 'firstName' => 'Ben', 'lastName' => 'Ole', 'status' => 'Inactive', 'workEmail' => 'ben@acme.com', 'hireDate' => '2019-02-01', 'terminationDate' => '2024-05-31', 'departmentId' => 46, 'departmentName' => 'Finance', 'reportsToId' => '123'],
        ], 'meta' => ['page' => ['nextCursor' => null]]]),
        'acme.bamboohr.com/api/v1/meta/lists' => Http::response([
            ['id' => 1, 'alias' => 'location', 'options' => [['id' => 9, 'name' => 'Aarhus', 'archived' => 'no']]],
            ['id' => 3, 'alias' => 'department', 'options' => [
                ['id' => 45, 'name' => 'Engineering', 'archived' => 'no'],
                ['id' => 46, 'name' => 'Finance', 'archived' => 'no'],
                ['id' => 47, 'name' => 'Old Team', 'archived' => 'yes'],
            ]],
        ]),
    ]);

    $credentials = ['subdomain' => 'acme', 'api_key' => 'bamboo-key'];
    $employees = hrisById((new BambooHrConnector)->fetchEmployees($credentials, new HrisSyncOptions));
    $departments = iterator_to_array((new BambooHrConnector)->fetchDepartments($credentials, new HrisSyncOptions), false);

    expect(array_map('strval', array_keys($employees)))->toBe(['123', '124', '140'])
        ->and($employees['123']->managerId)->toBe('101')
        ->and($employees['123']->departmentId)->toBe('45')
        ->and($employees['123']->employeeNumber)->toBe('E-0123')
        ->and($employees['124']->terminationDate)->toBeNull()
        ->and($employees['140']->status)->toBe(EmploymentStatus::Terminated)
        ->and(array_map(fn ($d) => [$d->id, $d->name], $departments))->toBe([['45', 'Engineering'], ['46', 'Finance']]);

    Http::assertSent(fn (Request $request): bool => str_contains($request->url(), 'page%5Bafter%5D=cur-2'));
    Http::assertSent(fn (Request $request): bool => $request->hasHeader('Authorization', 'Basic '.base64_encode('bamboo-key:x')));
});

it('reads only what changed in BambooHR, and a deleted employee arrives terminated', function (): void {
    Http::fake([
        'acme.bamboohr.com/api/v1/employees/changed*' => Http::response(['latest' => '2026-10-09T10:00:00+00:00', 'employees' => [
            '101' => ['id' => '101', 'action' => 'Updated', 'lastChanged' => '2026-10-09T09:00:00Z'],
            '102' => ['id' => '102', 'action' => 'Deleted', 'lastChanged' => '2026-10-09T09:30:00Z'],
        ]]),
        'acme.bamboohr.com/api/v1/employees?*' => Http::response(['data' => [
            ['employeeId' => '101', 'status' => 'Active', 'workEmail' => 'x@acme.com'],
        ], 'meta' => ['page' => ['nextCursor' => null]]]),
    ]);

    $employees = hrisById((new BambooHrConnector)->fetchEmployees(
        ['subdomain' => 'acme', 'api_key' => 'k'],
        new HrisSyncOptions(changedSince: Carbon::parse('2026-10-09T08:00:00Z')->toImmutable()),
    ));

    expect($employees['101']->email)->toBe('x@acme.com')
        ->and($employees['102']->status)->toBe(EmploymentStatus::Terminated)
        ->and($employees['102']->email)->toBeNull();

    Http::assertSent(fn (Request $request): bool => str_contains($request->url(), 'filter%5Bids%5D=101'));
    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), 'filter%5Bstatus%5D'));
});

it('follows Rippling\'s next_link, maps statuses, and never follows a link off its host', function (): void {
    Http::fake([
        'rest.ripplingapis.com/workers/?*cursor=page2*' => Http::response(['results' => [
            ['id' => 'w2', 'work_email' => 'tom@acme.com', 'status' => 'TERMINATED', 'start_date' => '2021-01-11', 'end_date' => '2024-09-30', 'department_id' => 'd2', 'manager_id' => 'w1', 'title' => 'AE', 'user' => ['name' => ['given_name' => 'Tom', 'family_name' => 'Lund'], 'display_name' => 'Tom Lund', 'number' => '1077']],
            ['id' => 'w3', 'work_email' => 'new@acme.com', 'status' => 'HIRED', 'start_date' => '2099-01-01'],
        ], 'next_link' => 'https://attacker.test/workers/?cursor=page3']),
        'rest.ripplingapis.com/workers/*' => Http::response(['results' => [
            ['id' => 'w1', 'work_email' => 'maya@acme.com', 'status' => 'ACTIVE', 'start_date' => '2022-03-01', 'end_date' => null, 'department_id' => 'd1', 'department' => ['id' => 'd1', 'name' => 'Engineering'], 'manager_id' => 'w0', 'title' => 'Staff Engineer', 'user' => ['name' => ['given_name' => 'Maya', 'family_name' => 'Berg'], 'display_name' => 'Maya Berg', 'number' => '1042'], 'work_location' => ['city' => 'Oslo']],
        ], 'next_link' => 'https://rest.ripplingapis.com/workers/?cursor=page2']),
        '*' => Http::response(['results' => [['id' => 'leaked', 'work_email' => 'evil@attacker.test']]]),
    ]);

    $employees = hrisById((new RipplingConnector)->fetchEmployees(['api_token' => 'rip-token'], new HrisSyncOptions(customAttributes: ['work_location.city'])));

    expect(array_map('strval', array_keys($employees)))->toBe(['w1', 'w2', 'w3'])
        ->and($employees['w1']->status)->toBe(EmploymentStatus::Active)
        ->and($employees['w1']->managerId)->toBe('w0')
        ->and($employees['w1']->employeeNumber)->toBe('1042')
        ->and($employees['w1']->departmentName)->toBe('Engineering')
        ->and($employees['w1']->customAttributes)->toBe(['work_location.city' => 'Oslo'])
        ->and($employees['w2']->status)->toBe(EmploymentStatus::Terminated)
        ->and($employees['w2']->terminationDate?->toDateString())->toBe('2024-09-30')
        ->and($employees['w3']->status)->toBe(EmploymentStatus::PreHire);

    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), 'attacker.test'));
    Http::assertSent(fn (Request $request): bool => $request->hasHeader('Authorization', 'Bearer rip-token'));
});

it('asks Rippling only for workers updated since the cursor', function (): void {
    Http::fake(['rest.ripplingapis.com/*' => Http::response(['results' => [], 'next_link' => null])]);

    iterator_to_array((new RipplingConnector)->fetchEmployees(['api_token' => 't'], new HrisSyncOptions(changedSince: Carbon::parse('2026-10-01T00:00:00Z')->toImmutable())));

    Http::assertSent(fn (Request $request): bool => str_contains(urldecode($request->url()), 'filter=updated_at ge 2026-10-01T00:00:00'));
});

it('searches HiBob people including inactive ones, reading nested and flat fields', function (): void {
    Http::fake([
        'api.hibob.com/v1/people/search' => Http::response(['employees' => [
            ['id' => '3332883911884669725', 'email' => 'amy@acme.com', 'firstName' => 'Amy', 'surname' => 'Miles', 'displayName' => 'Amy Miles', 'internal' => ['status' => 'Active', 'lifecycleStatus' => 'employed', 'terminationDate' => null], 'work' => ['startDate' => '2015-03-20', 'department' => '209192163', 'title' => 'Designer', 'employeeIdInCompany' => 39, 'reportsTo' => ['id' => '3332883909410030364', 'email' => 'zoe@acme.com']]],
            ['/root/id' => ['value' => '3332883911884669999'], '/root/email' => ['value' => 'jon@acme.com'], '/internal/lifecycleStatus' => ['value' => 'terminated'], '/internal/terminationDate' => ['value' => '2024-02-29'], '/work/manager' => ['value' => '3332883911884669725']],
            ['id' => '3', 'email' => 'p@acme.com', 'internal' => ['lifecycleStatus' => 'parental leave']],
            ['id' => '4', 'email' => 'g@acme.com', 'internal' => ['lifecycleStatus' => 'garden leave']],
        ]]),
        'api.hibob.com/v1/company/named-lists/department' => Http::response(['name' => 'department', 'items' => [
            ['id' => '209192163', 'value' => 'Design', 'name' => 'Design', 'archived' => false, 'children' => [
                ['id' => '209192164', 'value' => 'Brand', 'name' => 'Brand', 'archived' => false, 'children' => []],
            ]],
            ['id' => '209192170', 'value' => 'Gone', 'name' => 'Gone', 'archived' => true, 'children' => []],
        ]]),
    ]);

    $credentials = ['service_user_id' => 'SERVICE-1', 'service_user_token' => 'bob-token'];
    $employees = hrisById((new HiBobConnector)->fetchEmployees($credentials, new HrisSyncOptions));
    $departments = iterator_to_array((new HiBobConnector)->fetchDepartments($credentials, new HrisSyncOptions), false);

    expect($employees['3332883911884669725']->managerId)->toBe('3332883909410030364')
        ->and($employees['3332883911884669725']->departmentId)->toBe('209192163')
        ->and($employees['3332883911884669725']->employeeNumber)->toBe('39')
        ->and($employees['3332883911884669999']->status)->toBe(EmploymentStatus::Terminated)
        ->and($employees['3332883911884669999']->managerId)->toBe('3332883911884669725')
        ->and($employees['3']->status)->toBe(EmploymentStatus::OnLeave)
        ->and($employees['4']->status)->toBe(EmploymentStatus::Inactive)
        ->and(array_map(fn ($d) => [$d->id, $d->name, $d->parentId], $departments))->toBe([['209192163', 'Design', null], ['209192164', 'Brand', '209192163']]);

    Http::assertSent(fn (Request $request): bool => str_ends_with($request->url(), '/people/search')
        && $request['showInactive'] === true
        && in_array('internal.terminationDate', (array) $request['fields'], true)
        && $request->hasHeader('Authorization', 'Basic '.base64_encode('SERVICE-1:bob-token')));
});

it('pages Personio persons by cursor and reads each one\'s current employment', function (): void {
    Http::fake([
        'api.personio.de/v2/auth/token' => Http::response(['access_token' => 'pers-token', 'token_type' => 'Bearer', 'expires_in' => 86400]),
        'api.personio.de/v2/persons/5005/employments*' => Http::response(['_data' => [
            ['id' => '6999', 'status' => 'INACTIVE', 'employment_start_date' => '2018-01-01'],
            ['id' => '7001', 'status' => 'ACTIVE', 'employment_start_date' => '2020-02-01', 'supervisor' => ['id' => '5000'], 'org_units' => [['type' => 'department', 'id' => '401'], ['type' => 'team', 'id' => '4502']], 'position' => ['title' => 'Software Engineer']],
        ], '_meta' => ['links' => []]]),
        'api.personio.de/v2/persons/5012/employments*' => Http::response(['_data' => [
            ['id' => '7010', 'status' => 'INACTIVE', 'employment_start_date' => '2020-02-01', 'termination' => ['termination_date' => '2024-12-31'], 'supervisor' => ['id' => '5005']],
        ], '_meta' => ['links' => []]]),
        'api.personio.de/v2/persons?*cursor=cur2*' => Http::response(['_data' => [
            ['id' => '5012', 'email' => 'max@acme.de', 'first_name' => 'Max', 'last_name' => 'Weber', 'status' => 'INACTIVE'],
        ], '_meta' => ['links' => ['self' => ['href' => 'x']]]]),
        'api.personio.de/v2/persons?*' => Http::response(['_data' => [
            ['id' => '5005', 'email' => 'lena@acme.de', 'first_name' => 'Lena', 'last_name' => 'Koch', 'preferred_name' => 'Lena Koch', 'status' => 'ACTIVE', 'custom_attributes' => [['id' => 'dynamic_1', 'global_id' => '1', 'label' => 'Cost centre', 'value' => 'CC-7']]],
        ], '_meta' => ['links' => ['next' => ['href' => 'https://api.personio.de/v2/persons?cursor=cur2']]]]),
        'api.personio.de/v2/org-units*' => Http::response(['_data' => [['id' => '401', 'name' => 'Platform', 'type' => 'department', 'parent_id' => null]], '_meta' => ['links' => []]]),
    ]);

    $credentials = ['client_id' => 'papi-1', 'client_secret' => 'psecret'];
    $employees = hrisById((new PersonioConnector)->fetchEmployees($credentials, new HrisSyncOptions(customAttributes: ['Cost centre'])));
    $departments = iterator_to_array((new PersonioConnector)->fetchDepartments($credentials, new HrisSyncOptions), false);

    expect(array_map('strval', array_keys($employees)))->toBe(['5005', '5012'])
        ->and($employees['5005']->status)->toBe(EmploymentStatus::Active)
        ->and($employees['5005']->managerId)->toBe('5000')
        ->and($employees['5005']->departmentId)->toBe('401')
        ->and($employees['5005']->jobTitle)->toBe('Software Engineer')
        ->and($employees['5005']->customAttributes)->toBe(['Cost centre' => 'CC-7'])
        ->and($employees['5012']->status)->toBe(EmploymentStatus::Terminated)
        ->and($employees['5012']->managerId)->toBe('5005')
        ->and($departments[0]->name)->toBe('Platform');

    Http::assertSent(fn (Request $request): bool => str_ends_with($request->url(), '/v2/auth/token')
        && $request['grant_type'] === 'client_credentials' && $request['client_id'] === 'papi-1');
});

it('retries a 429 honouring Retry-After, then carries on', function (): void {
    Http::fake([
        'rest.ripplingapis.com/*' => Http::sequence()
            ->push(['error' => 'rate limited'], 429, ['Retry-After' => '7'])
            ->push(['error' => 'busy'], 503)
            ->push(['results' => [['id' => 'w1', 'work_email' => 'a@acme.com', 'status' => 'ACTIVE']], 'next_link' => null]),
    ]);

    $employees = hrisById((new RipplingConnector)->fetchEmployees(['api_token' => 't'], new HrisSyncOptions));

    expect($employees)->toHaveKey('w1');
    Sleep::assertSequence([Sleep::for(7)->seconds(), Sleep::for(4)->seconds()]);
});

it('reads a rate-limit reset timestamp when there is no Retry-After', function (): void {
    Carbon::setTestNow('2026-10-09 12:00:00');

    Http::fake([
        'api.hibob.com/v1/people/search' => Http::sequence()
            ->push([], 429, ['X-RateLimit-Reset' => (string) (Carbon::now()->getTimestamp() + 12)])
            ->push(['employees' => []]),
    ]);

    iterator_to_array((new HiBobConnector)->fetchEmployees(['service_user_id' => 'a', 'service_user_token' => 'b'], new HrisSyncOptions));

    Sleep::assertSequence([Sleep::for(12)->seconds()]);
    Carbon::setTestNow();
});

it('gives up after the configured attempts and says it was rate limited', function (): void {
    config(['cbox-id.directory.hris.max_attempts' => 3]);
    Http::fake(['rest.ripplingapis.com/*' => Http::response([], 429)]);

    expect(fn () => iterator_to_array((new RipplingConnector)->fetchEmployees(['api_token' => 't'], new HrisSyncOptions)))
        ->toThrow(DirectoryConnectionFailed::class, 'rate limited (429) after 3 attempts');

    Http::assertSentCount(3);
});

it('does not retry refused credentials, and never puts them in the message', function (): void {
    Http::fake(['acme.bamboohr.com/*' => Http::response(['error' => 'nope'], 401)]);

    try {
        (new BambooHrConnector)->probe(['subdomain' => 'acme', 'api_key' => 'super-secret-key']);
        $this->fail('The probe should have been refused.');
    } catch (DirectoryConnectionFailed $e) {
        expect($e->getMessage())->toContain('401')
            ->and($e->getMessage())->toContain('credentials were refused')
            ->and($e->getMessage())->not->toContain('super-secret-key');
    }

    Http::assertSentCount(1);
    expect((new BambooHrConnector)->verify(['subdomain' => 'acme', 'api_key' => 'k']))->toBeFalse();
});
