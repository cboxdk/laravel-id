<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->fixture = tempnam(sys_get_temp_dir(), 'cbox-import-').'.csv';
});

afterEach(function (): void {
    if (is_string($this->fixture ?? null)) {
        @unlink($this->fixture);
    }
});

it('imports a CSV fixture and reports the right counts', function (): void {
    config(['hashing.driver' => 'argon2id']);

    $org = $this->makeOrganization();
    $bcrypt = password_hash('s3cret', PASSWORD_BCRYPT);

    file_put_contents($this->fixture, implode("\n", [
        'email,name,password_hash,password,email_verified,role',
        "alice@corp.test,Alice,{$bcrypt},,1,member",
        'bob@corp.test,Bob,,plain-pw,0,admin',
    ])."\n");

    $this->artisan('cbox-id:users:import', [
        'file' => $this->fixture,
        '--org' => $org->id,
        '--format' => 'csv',
    ])->assertExitCode(0);

    $subjects = app(Subjects::class);
    $alice = $subjects->findByEmail('alice@corp.test');
    $bob = $subjects->findByEmail('bob@corp.test');

    expect($alice)->not->toBeNull()
        ->and($bob)->not->toBeNull()
        // The imported bcrypt hash authenticates day-one.
        ->and($subjects->verifyPassword($alice?->id ?? '', 's3cret'))->toBeTrue()
        // The plaintext password was hashed and works.
        ->and($subjects->verifyPassword($bob?->id ?? '', 'plain-pw'))->toBeTrue();
});

it('exits non-zero when a row cannot be imported', function (): void {
    $org = $this->makeOrganization();

    file_put_contents($this->fixture, implode("\n", [
        'email,name,password',
        'good@corp.test,Good,pw',
        'not-an-email,Bad,pw',
    ])."\n");

    $this->artisan('cbox-id:users:import', [
        'file' => $this->fixture,
        '--org' => $org->id,
    ])->assertExitCode(1);

    // The good row still imported (one bad row never discards the good ones).
    expect(app(Subjects::class)->findByEmail('good@corp.test'))->not->toBeNull();
});

it('refuses to import when the active environment is not the org\'s', function (): void {
    // The org lives in the default test environment; act as an unrelated one so
    // the ambient environment no longer matches the target org's plane.
    $org = $this->makeOrganization();
    $this->actingAsEnvironment('env_other');

    file_put_contents($this->fixture, "email\nstray@corp.test\n");

    $this->artisan('cbox-id:users:import', [
        'file' => $this->fixture,
        '--org' => $org->id,
    ])->assertExitCode(1);

    // Nothing was written into the wrong plane.
    expect($this->withoutEnvironmentScope(
        fn () => app(Subjects::class)->findByEmail('stray@corp.test'),
    ))->toBeNull();
});

it('fails cleanly when the file is missing', function (): void {
    $org = $this->makeOrganization();

    $this->artisan('cbox-id:users:import', [
        'file' => '/no/such/file.csv',
        '--org' => $org->id,
    ])->assertExitCode(1);
});

it('requires the --org option', function (): void {
    file_put_contents($this->fixture, "email\nx@corp.test\n");

    $this->artisan('cbox-id:users:import', [
        'file' => $this->fixture,
    ])->assertExitCode(1);
});
