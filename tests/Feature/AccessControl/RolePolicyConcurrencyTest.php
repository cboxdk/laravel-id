<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\RoleDefinitions;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\RoleSource;
use Cbox\Id\AccessControl\Exceptions\GrantRefused;
use Cbox\Id\AccessControl\Exceptions\RoleNotTenantAssignable;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\EnvironmentRoleAssignment;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('rechecks role policy after a concurrent catalog change commits', function (string $change, string $grant): void {
    $this->fakeAudit();
    $this->fakeEvents();
    $roles = app(Roles::class);
    $role = $roles->define(null, 'Concurrent policy '.bin2hex(random_bytes(5)));
    if ($change === 'activate') {
        $role->update([
            'source' => RoleSource::Manifest,
            'pending_definition_version' => 'reviewed-staff-definition',
            'pending_permission_keys' => [],
            'pending_tenant_assignable' => false,
        ]);
    }
    DB::commit();
    DB::disconnect();
    $directory = sys_get_temp_dir().'/role-policy-race-'.bin2hex(random_bytes(8));
    mkdir($directory);
    $application = 'role-policy-'.bin2hex(random_bytes(8));
    $pid = pcntl_fork();
    expect($pid)->not->toBe(-1);
    if ($pid === 0) {
        try {
            DB::select("select set_config('application_name', ?, false)", [$application]);
            $deadline = microtime(true) + 15;
            while (! file_exists($directory.'/go') && microtime(true) < $deadline) {
                usleep(1000);
            }
            match ($grant) {
                'everywhere' => $roles->assignEverywhere('race-user', $role->id),
                'operator' => $roles->assign('race-org', 'race-user', $role->id),
                default => $roles->assignAsTenant('race-org', 'race-user', $role->id),
            };
            $result = 'granted';
        } catch (RoleNotTenantAssignable|UnknownRole $exception) {
            $result = $exception::class;
        } catch (Throwable $exception) {
            $result = 'ERROR: '.$exception::class.': '.$exception->getMessage();
        }
        file_put_contents($directory.'/result', $result);
        posix_kill(posix_getpid(), SIGKILL);
    }

    $blocked = false;
    try {
        DB::beginTransaction();
        match ($change) {
            'activate' => app(RoleDefinitions::class)->activate($role->id, 'reviewed-staff-definition', AuditActor::operator('policy-reviewer')),
            'delete' => $roles->deleteRole($role->id),
            default => $roles->updateRole($role->id, $role->name, tenantAssignable: false),
        };
        touch($directory.'/go');
        $deadline = microtime(true) + 10;
        do {
            DB::select('select pg_stat_clear_snapshot()');
            $waiting = DB::selectOne('select wait_event_type from pg_stat_activity where application_name = ?', [$application]);
            $blocked = $waiting !== null && $waiting->wait_event_type === 'Lock';
            if ($blocked || file_exists($directory.'/result')) {
                break;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        DB::commit();
        pcntl_waitpid($pid, $status);
        $result = file_get_contents($directory.'/result');
        expect($blocked)->toBeTrue('The grant must wait on the role policy transaction, not read the old assignable state.')
            ->and($result)->toBe($grant === 'tenant' ? RoleNotTenantAssignable::class : UnknownRole::class)
            ->and(RoleAssignment::query()->where('role_id', $role->id)->count())->toBe(0)
            ->and(EnvironmentRoleAssignment::query()->where('role_id', $role->id)->count())->toBe(0);
    } finally {
        if (DB::transactionLevel() > 0) {
            DB::rollBack();
        }
        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status, WNOHANG);
        RoleAssignment::query()->where('role_id', $role->id)->delete();
        EnvironmentRoleAssignment::query()->where('role_id', $role->id)->delete();
        Role::query()->whereKey($role->id)->delete();
        foreach (glob($directory.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($directory);
        DB::beginTransaction();
    }
})->with([
    'staff update versus tenant grant' => ['update', 'tenant'],
    'definition activation versus tenant grant' => ['activate', 'tenant'],
    'delete versus tenant grant' => ['delete', 'tenant'],
    'delete versus operator grant' => ['delete', 'operator'],
    'delete versus environment grant' => ['delete', 'everywhere'],
])->skip(fn (): bool => DB::connection()->getDriverName() !== 'pgsql' || ! function_exists('pcntl_fork'), 'needs PostgreSQL and pcntl');

it('serializes different conflicting roles for the same subject', function (): void {
    $this->fakeAudit();
    $this->fakeEvents();
    $roles = app(Roles::class);
    $first = $roles->define('race-org', 'Payment creator');
    $second = $roles->define('race-org', 'Payment approver');
    $policy = app(SegregationOfDuties::class)
        ->definePolicy('race-org', 'No self-approved payments', [$first->id, $second->id]);
    DB::commit();
    DB::disconnect();
    $directory = sys_get_temp_dir().'/role-sod-race-'.bin2hex(random_bytes(8));
    mkdir($directory);
    $application = 'role-sod-'.bin2hex(random_bytes(8));
    $pid = pcntl_fork();
    expect($pid)->not->toBe(-1);
    if ($pid === 0) {
        try {
            DB::select("select set_config('application_name', ?, false)", [$application]);
            $deadline = microtime(true) + 15;
            while (! file_exists($directory.'/go') && microtime(true) < $deadline) {
                usleep(1000);
            }
            $roles->assignAsTenant('race-org', 'sod-subject', $second->id);
            $result = 'granted';
        } catch (GrantRefused $exception) {
            $result = 'refused';
        } catch (Throwable $exception) {
            $result = 'ERROR: '.$exception::class.': '.$exception->getMessage();
        }
        file_put_contents($directory.'/result', $result);
        posix_kill(posix_getpid(), SIGKILL);
    }
    $blocked = false;
    try {
        DB::beginTransaction();
        $roles->assignAsTenant('race-org', 'sod-subject', $first->id);
        touch($directory.'/go');
        $deadline = microtime(true) + 10;
        do {
            DB::select('select pg_stat_clear_snapshot()');
            $waiting = DB::selectOne('select wait_event_type from pg_stat_activity where application_name = ?', [$application]);
            $blocked = $waiting !== null && $waiting->wait_event_type === 'Lock';
            if ($blocked || file_exists($directory.'/result')) {
                break;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        DB::commit();
        pcntl_waitpid($pid, $status);
        expect($blocked)->toBeTrue('Different role rows must share a subject lock before checking conflicts.')
            ->and(file_get_contents($directory.'/result'))->toBe('refused')
            ->and($roles->assignmentsForSubject('race-org', 'sod-subject'))->toBe([$first->id]);
    } finally {
        if (DB::transactionLevel() > 0) {
            DB::rollBack();
        }
        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status, WNOHANG);
        RoleAssignment::query()->whereIn('role_id', [$first->id, $second->id])->delete();
        Role::query()->whereIn('id', [$first->id, $second->id])->delete();
        $policy->delete();
        foreach (glob($directory.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($directory);
        DB::beginTransaction();
    }
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'pgsql' || ! function_exists('pcntl_fork'), 'needs PostgreSQL and pcntl');
