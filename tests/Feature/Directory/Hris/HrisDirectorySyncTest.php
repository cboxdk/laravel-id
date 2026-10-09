<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\PullDirectories;
use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Enums\DirectorySyncStatus;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Exceptions\DirectorySyncInProgress;
use Cbox\Id\Directory\Hris\Enums\EmploymentStatus;
use Cbox\Id\Directory\Hris\HrisEmployeeMapper;
use Cbox\Id\Directory\Hris\ValueObjects\HrisDepartment;
use Cbox\Id\Directory\Hris\ValueObjects\HrisEmployee;
use Cbox\Id\Directory\Jobs\SyncPullDirectory;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\Testing\FakeHrisProvider;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * The HR-aware sync: employment dates decide access, leavers who never had an account
 * get none, departments become groups, one bad record costs one record, a mass
 * deprovisioning is refused, and an incremental run deprovisions nobody for being absent.
 */
function hrisEmployee(string $id, ?string $email = null, EmploymentStatus $status = EmploymentStatus::Active, array $extra = []): HrisEmployee
{
    return new HrisEmployee(...[
        'id' => $id,
        'email' => $email ?? "{$id}@acme.com",
        'status' => $status,
        'firstName' => ucfirst($id),
        'lastName' => 'Person',
        ...$extra,
    ]);
}

/**
 * @return array{0: Directory, 1: FakeHrisProvider}
 */
function hrisDirectory(FakeHrisProvider $fake, string $slug = 'acme'): array
{
    $org = app(Organizations::class)->create(new NewOrganization(ucfirst($slug), $slug));
    app()->instance(DirectoryConnectors::class, new DirectoryConnectors([$fake]));

    $directory = app(Directories::class)->registerPull($org->id, 'BambooHR', $fake->provider(), [
        'subdomain' => $slug, 'api_key' => 'secret-api-key-'.$slug,
    ]);

    return [$directory, $fake];
}

function hrisActive(Directory $directory): array
{
    return DirectoryUser::query()->where('directory_id', $directory->id)->where('active', true)
        ->pluck('external_id')->map(fn ($id) => (string) $id)->sort()->values()->all();
}

it('provisions the employed, skips leavers and pre-hires who never had an account, and records the run', function (): void {
    [$directory] = hrisDirectory(new FakeHrisProvider(employees: [
        hrisEmployee('ada', extra: ['managerId' => 'grace', 'departmentId' => 'd1', 'departmentName' => 'Engineering', 'jobTitle' => 'Engineer', 'employeeNumber' => 'E1', 'startDate' => CarbonImmutable::parse('2020-01-01'), 'customAttributes' => ['costCenter' => 'CC-7']]),
        hrisEmployee('grace', extra: ['departmentId' => 'd1', 'departmentName' => 'Engineering']),
        hrisEmployee('leah', status: EmploymentStatus::OnLeave),
        hrisEmployee('old', status: EmploymentStatus::Terminated, extra: ['terminationDate' => CarbonImmutable::parse('2019-05-31')]),
        hrisEmployee('newbie', status: EmploymentStatus::Active, extra: ['startDate' => CarbonImmutable::now()->addDays(10)]),
    ], departments: [new HrisDepartment('d1', 'Engineering'), new HrisDepartment('d2', 'Sales')]));

    $result = app(DirectoryPullSync::class)->sync($directory);

    expect($result->provisioned)->toBe(3)
        ->and($result->skipped)->toBe(2)
        ->and($result->failed)->toBe(0)
        ->and($result->incremental)->toBeFalse()
        ->and(hrisActive($directory))->toBe(['ada', 'grace', 'leah'])
        ->and(DirectoryUser::query()->where('directory_id', $directory->id)->count())->toBe(3);

    $ada = DirectoryUser::query()->where('directory_id', $directory->id)->where('external_id', 'ada')->sole();
    expect($ada->resource[ScimSchema::ENTERPRISE_URN]['manager'])->toBe(['value' => 'grace'])
        ->and($ada->resource[ScimSchema::ENTERPRISE_URN]['department'])->toBe('Engineering')
        ->and($ada->resource[ScimSchema::ENTERPRISE_URN]['employeeNumber'])->toBe('E1')
        ->and($ada->resource['title'])->toBe('Engineer')
        ->and($ada->resource[HrisEmployeeMapper::SCHEMA]['startDate'])->toBe('2020-01-01')
        ->and($ada->resource[HrisEmployeeMapper::SCHEMA]['customAttributes'])->toBe(['costCenter' => 'CC-7'])
        ->and($ada->resource[HrisEmployeeMapper::SCHEMA]['employmentStatus'])->toBe('active');

    // Departments are groups, members the employed people filed under them; an empty
    // department is still offered, so a role can be mapped before anybody joins it.
    $groups = DirectoryGroup::query()->where('directory_id', $directory->id)->with('members')->get()->keyBy('external_id');
    expect($groups->keys()->sort()->values()->all())->toBe(['department:d1', 'department:d2'])
        ->and($groups['department:d1']->display_name)->toBe('Engineering')
        ->and($groups['department:d1']->members->pluck('external_id')->sort()->values()->all())->toBe(['ada', 'grace'])
        ->and($groups['department:d2']->members)->toHaveCount(0);

    $directory->refresh();
    expect($directory->last_sync_status)->toBe(DirectorySyncStatus::Succeeded)
        ->and($directory->last_sync_error)->toBeNull()
        ->and($directory->last_sync_started_at)->not->toBeNull()
        ->and($directory->last_full_sync_at)->not->toBeNull()
        ->and($directory->sync_cursor)->toBeNull()
        ->and($directory->last_sync_stats)->toMatchArray(['mode' => 'full', 'provisioned' => 3, 'skipped' => 2, 'failed' => 0]);
});

it('deprovisions a leaver, and anybody a full pull no longer returns', function (): void {
    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(employees: [
        hrisEmployee('ada'), hrisEmployee('bo'), hrisEmployee('cy'),
    ]));

    app(DirectoryPullSync::class)->sync($directory);

    $bo = DirectoryUser::query()->where('directory_id', $directory->id)->where('external_id', 'bo')->sole();

    $fake->returns([
        hrisEmployee('ada'),
        hrisEmployee('bo', status: EmploymentStatus::Terminated, extra: ['terminationDate' => CarbonImmutable::now()->subDay()]),
    ]);

    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    expect($result->deprovisioned)->toBe(2)
        ->and(hrisActive($directory))->toBe(['ada'])
        ->and(app(Subjects::class)->isActive((string) $bo->user_id))->toBeFalse();
});

it('keeps access until the end of the last day, and the dates win over the status word', function (): void {
    $mapper = new HrisEmployeeMapper(preHireDays: 3, now: CarbonImmutable::parse('2026-10-09 15:00'));

    expect($mapper->effectiveStatus(hrisEmployee('a', extra: ['terminationDate' => CarbonImmutable::parse('2026-10-09')])))->toBe(EmploymentStatus::Active)
        ->and($mapper->effectiveStatus(hrisEmployee('b', extra: ['terminationDate' => CarbonImmutable::parse('2026-10-08')])))->toBe(EmploymentStatus::Terminated)
        ->and($mapper->effectiveStatus(hrisEmployee('c', status: EmploymentStatus::PreHire, extra: ['startDate' => CarbonImmutable::parse('2026-10-12')])))->toBe(EmploymentStatus::Active)
        ->and($mapper->effectiveStatus(hrisEmployee('d', extra: ['startDate' => CarbonImmutable::parse('2026-10-13')])))->toBe(EmploymentStatus::PreHire)
        ->and($mapper->effectiveStatus(hrisEmployee('e', status: EmploymentStatus::OnLeave)))->toBe(EmploymentStatus::OnLeave)
        ->and($mapper->toScimUser(hrisEmployee('f', email: 'not-an-email'), DirectoryProvider::BambooHr))->toBeNull();
});

it('deactivates somebody whose termination date passed even when their record did not change', function (): void {
    Carbon::setTestNow('2026-10-09 09:00');

    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(incremental: true, employees: [
        hrisEmployee('ada'),
        hrisEmployee('bo', extra: ['terminationDate' => CarbonImmutable::parse('2026-10-09')]),
    ]));

    app(DirectoryPullSync::class)->sync($directory);
    expect(hrisActive($directory))->toBe(['ada', 'bo']);

    // The next morning: an incremental run, and nothing changed in the HR system.
    Carbon::setTestNow('2026-10-10 07:00');
    $fake->changed([]);

    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    expect($result->incremental)->toBeTrue()
        ->and($result->deprovisioned)->toBe(1)
        ->and(hrisActive($directory))->toBe(['ada']);

    Carbon::setTestNow();
});

it('runs incrementally between full pulls, and an incremental run deprovisions nobody for being absent', function (): void {
    Carbon::setTestNow('2026-10-09 09:00');

    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(incremental: true, employees: [
        hrisEmployee('ada'), hrisEmployee('bo'),
    ]));

    app(DirectoryPullSync::class)->sync($directory);
    expect($fake->lastOptions?->changedSince)->toBeNull()
        ->and($directory->fresh()->sync_cursor)->toBe('2026-10-09T09:00:00+00:00');

    Carbon::setTestNow('2026-10-09 10:00');
    $fake->changed([hrisEmployee('cy')]);

    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    // Asked for what changed since the last run started, wound back against clock skew.
    expect($result->incremental)->toBeTrue()
        ->and($fake->lastOptions?->changedSince?->toIso8601String())->toBe('2026-10-09T08:55:00+00:00')
        ->and(hrisActive($directory))->toBe(['ada', 'bo', 'cy']);

    // A full pull a day later — and only a full pull — deprovisions who is gone.
    Carbon::setTestNow('2026-10-10 09:30');
    $fake->returns([hrisEmployee('ada'), hrisEmployee('cy')]);

    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    expect($result->incremental)->toBeFalse()
        ->and(hrisActive($directory))->toBe(['ada', 'cy']);

    // `full` forces one before the day is up.
    Carbon::setTestNow('2026-10-10 10:00');
    app(DirectoryPullSync::class)->sync($directory->fresh(), full: true);
    expect($fake->lastOptions?->changedSince)->toBeNull();

    Carbon::setTestNow();
});

it('reports a record it cannot reconcile without failing the run, and without naming the person', function (): void {
    app(Subjects::class)->create('taken@acme.com', 'Somebody Else');

    [$directory] = hrisDirectory(new FakeHrisProvider(employees: [
        hrisEmployee('ada'),
        hrisEmployee('dup', email: 'taken@acme.com'),
        hrisEmployee('noemail', email: ''),
    ]));

    $result = app(DirectoryPullSync::class)->sync($directory);

    expect($result->provisioned)->toBe(1)
        ->and($result->failed)->toBe(2)
        ->and($result->partial())->toBeTrue()
        ->and(array_map(fn ($f) => $f->externalId, $result->failures))->toBe(['dup', 'noemail'])
        ->and(hrisActive($directory))->toBe(['ada']);

    $directory->refresh();
    expect($directory->last_sync_status)->toBe(DirectorySyncStatus::Partial)
        ->and($directory->last_sync_error)->toContain('2 records could not be synced')
        ->and($directory->last_sync_error)->not->toContain('taken@acme.com')
        ->and(json_encode($directory->last_sync_stats))->not->toContain('taken@acme.com');
});

it('never deprovisions somebody the HR system still reports, even when their record cannot be synced', function (): void {
    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(employees: [hrisEmployee('ada'), hrisEmployee('bo')]));

    app(DirectoryPullSync::class)->sync($directory);

    // Bo's work email was removed in the HR system; Bo is still employed.
    $fake->returns([hrisEmployee('ada'), hrisEmployee('bo', email: '')]);
    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    expect($result->deprovisioned)->toBe(0)
        ->and($result->failed)->toBe(1)
        ->and(hrisActive($directory))->toBe(['ada', 'bo']);
});

it('refuses a mass deprovisioning that looks like an integration that lost its reach', function (): void {
    $everyone = array_map(fn (int $i) => hrisEmployee('p'.$i), range(1, 12));
    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(employees: $everyone));

    app(DirectoryPullSync::class)->sync($directory);

    $fake->returns(array_slice($everyone, 0, 3));
    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    expect($result->deprovisioned)->toBe(0)
        ->and($result->failures[0]->reason)->toContain('Refused to deprovision 9 of 12')
        ->and(hrisActive($directory))->toHaveCount(12)
        ->and($directory->fresh()->last_sync_status)->toBe(DirectorySyncStatus::Partial);

    // Somebody who means it turns the guard off.
    config(['cbox-id.directory.hris.deprovision_guard' => 1]);
    $result = app(DirectoryPullSync::class)->sync($directory->fresh());

    expect($result->deprovisioned)->toBe(9)->and(hrisActive($directory))->toHaveCount(3);
});

it('keeps two departments with the same name apart, and removes a department that is gone and empty', function (): void {
    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(
        employees: [hrisEmployee('ada', extra: ['departmentId' => 's1']), hrisEmployee('bo', extra: ['departmentId' => 's2'])],
        departments: [new HrisDepartment('s1', 'Sales'), new HrisDepartment('s2', 'Sales'), new HrisDepartment('old', 'Legacy')],
    ));

    app(DirectoryPullSync::class)->sync($directory);

    $names = DirectoryGroup::query()->where('directory_id', $directory->id)->pluck('display_name')->sort()->values()->all();
    expect($names)->toBe(['Legacy', 'Sales (s1)', 'Sales (s2)']);

    $fake->returnsDepartments([new HrisDepartment('s1', 'Sales EMEA'), new HrisDepartment('s2', 'Sales')]);
    app(DirectoryPullSync::class)->sync($directory->fresh());

    $names = DirectoryGroup::query()->where('directory_id', $directory->id)->pluck('display_name')->sort()->values()->all();
    expect($names)->toBe(['Sales', 'Sales EMEA']);
});

it('records a refused pull as failed and writes nobody', function (): void {
    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(employees: [hrisEmployee('ada')]));
    $fake->refuses('The employee list request failed (403): the credentials lack permission to read employees.');

    expect(fn () => app(DirectoryPullSync::class)->sync($directory))->toThrow(DirectoryConnectionFailed::class);

    $directory->refresh();
    expect($directory->last_sync_status)->toBe(DirectorySyncStatus::Failed)
        ->and($directory->last_sync_error)->toContain('403')
        ->and(DirectoryUser::query()->where('directory_id', $directory->id)->count())->toBe(0);
});

it('never syncs one directory twice at once', function (): void {
    [$directory] = hrisDirectory(new FakeHrisProvider(employees: [hrisEmployee('ada')]));

    $lock = Cache::lock('cbox-id:directory-sync:'.$directory->id, 60);
    $lock->get();

    expect(fn () => app(DirectoryPullSync::class)->sync($directory))->toThrow(DirectorySyncInProgress::class)
        ->and($directory->fresh()->last_sync_error)->toBeNull();

    $lock->release();
    expect(app(DirectoryPullSync::class)->sync($directory->fresh())->provisioned)->toBe(1);
});

it('seals the credentials and never serializes them', function (): void {
    [$directory] = hrisDirectory(new FakeHrisProvider(employees: []));

    $raw = DB::table('directories')->where('id', $directory->id)->value('credentials');

    expect($raw)->toBeString()->not->toContain('secret-api-key-acme')
        ->and($directory->toArray())->not->toHaveKey('credentials')
        ->and($directory->toArray())->not->toHaveKey('bearer_token_hash')
        ->and(json_encode($directory))->not->toContain('secret-api-key');

    $directory->forceFill(['sync_cursor' => '2026-10-09T00:00:00+00:00'])->save();
    app(PullDirectories::class)->replaceCredentials($directory, ['subdomain' => 'acme', 'api_key' => 'rotated-key']);

    $directory->refresh();
    expect(DB::table('directories')->where('id', $directory->id)->value('credentials'))->not->toBe($raw)->not->toContain('rotated-key')
        ->and($directory->sync_cursor)->toBeNull();
});

it('passes the configured custom attributes and paces each directory on its own interval', function (): void {
    [$directory, $fake] = hrisDirectory(new FakeHrisProvider(employees: [hrisEmployee('ada')]));

    app(PullDirectories::class)->setHrisOptions($directory, ['costCenter', ' ', 'costCenter', 'location']);
    app(PullDirectories::class)->setSyncInterval($directory, 5);

    expect($directory->fresh()->sync_interval_minutes)->toBe(Directory::MIN_SYNC_INTERVAL_MINUTES);

    app(DirectoryPullSync::class)->sync($directory->fresh());
    expect($fake->lastOptions?->customAttributes)->toBe(['costCenter', 'location']);

    Carbon::setTestNow(Carbon::now()->addMinutes(10));
    expect($directory->fresh()->isDueForSync())->toBeFalse();
    Carbon::setTestNow(Carbon::now()->addMinutes(5));
    expect($directory->fresh()->isDueForSync())->toBeTrue();
    Carbon::setTestNow();
});

it('pulls only the due directories when scheduled', function (): void {
    [$due] = hrisDirectory(new FakeHrisProvider(employees: [hrisEmployee('ada')]), 'due');
    $notDue = app(Directories::class)->registerPull(
        app(Organizations::class)->create(new NewOrganization('Fresh', 'fresh'))->id,
        'BambooHR', DirectoryProvider::BambooHr, ['subdomain' => 'fresh', 'api_key' => 'k'],
    );
    $notDue->forceFill(['last_sync_started_at' => now()->subMinutes(10)])->save();
    $due->forceFill(['last_sync_started_at' => now()->subHours(2)])->save();

    $this->artisan('cbox-id:directory:sync', ['--due' => true])->assertSuccessful();

    expect($due->fresh()->last_sync_status)->toBe(DirectorySyncStatus::Succeeded)
        ->and($notDue->fresh()->last_sync_status)->toBeNull();
});

it('syncs from a queued job that carries only the directory id', function (): void {
    [$directory] = hrisDirectory(new FakeHrisProvider(employees: [hrisEmployee('ada')]));

    $job = new SyncPullDirectory($directory->id);
    expect(serialize($job))->not->toContain('secret-api-key');

    dispatch_sync($job);

    expect(hrisActive($directory))->toBe(['ada']);
});

it('keeps each environment\'s HR directory to its own environment', function (): void {
    $fake = new FakeHrisProvider(employees: [hrisEmployee('ada')]);
    app()->instance(DirectoryConnectors::class, new DirectoryConnectors([$fake]));

    $make = fn (string $slug) => app(Directories::class)->registerPull(
        app(Organizations::class)->create(new NewOrganization(ucfirst($slug), $slug))->id,
        'BambooHR', DirectoryProvider::BambooHr, ['subdomain' => $slug, 'api_key' => 'k-'.$slug],
    );

    $a = $this->runAsEnvironment('env_a', fn () => $make('acme'));
    $b = $this->runAsEnvironment('env_b', fn () => $make('globex'));

    // The scheduled command runs with no environment pinned, and syncs each in its own.
    $this->artisan('cbox-id:directory:sync')->assertSuccessful();

    $this->runAsEnvironment('env_a', function () use ($a, $b): void {
        expect(DirectoryUser::query()->pluck('directory_id')->unique()->values()->all())->toBe([$a->id])
            ->and(Directory::query()->whereKey($b->id)->exists())->toBeFalse();
    });

    $this->runAsEnvironment('env_b', function () use ($b): void {
        expect(DirectoryUser::query()->pluck('directory_id')->unique()->values()->all())->toBe([$b->id])
            ->and(DirectoryUser::query()->value('environment_id'))->toBe('env_b');
    });
});
