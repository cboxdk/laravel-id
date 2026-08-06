<?php

declare(strict_types=1);

use Cbox\Id\Console\Contracts\HealthCheck;
use Cbox\Id\Console\Enums\HealthStatus;
use Cbox\Id\Console\HealthChecks;
use Cbox\Id\Console\ValueObjects\HealthResult;

it('runs what the host contributed', function (): void {
    $checks = app(HealthChecks::class);
    $checks->add(new class implements HealthCheck
    {
        public function run(): array
        {
            return [HealthResult::ok('Host check ran')];
        }
    });

    $results = $checks->run();

    expect($results)->toHaveCount(1)
        ->and($results[0]->label)->toBe('Host check ran')
        ->and($results[0]->status)->toBe(HealthStatus::Ok);
});

it('survives a check that throws instead of hiding every other finding', function (): void {
    // The contract says a check must not throw. This assumes it will anyway: the moment
    // you most want a health report is when something is already broken enough to throw,
    // and a doctor that dies on the host's second check hides the third and its own.
    $checks = app(HealthChecks::class);

    $checks->add(new class implements HealthCheck
    {
        public function run(): array
        {
            throw new RuntimeException('the database is gone');
        }
    });
    $checks->add(new class implements HealthCheck
    {
        public function run(): array
        {
            return [HealthResult::ok('Still reported')];
        }
    });

    $results = $checks->run();

    expect($results)->toHaveCount(2)
        ->and($results[0]->status)->toBe(HealthStatus::Fail)
        ->and($results[0]->detail)->toBe('the database is gone')
        // The finding AFTER the throwing one still gets reported. That is the point.
        ->and($results[1]->label)->toBe('Still reported');
});

it('reports a host check inside the doctor output', function (): void {
    app(HealthChecks::class)->add(new class implements HealthCheck
    {
        public function run(): array
        {
            return [HealthResult::fail('Deployment claims a shape it cannot serve', 'Set the account host.')];
        }
    });

    // End to end through the command, because a registry nothing renders is a registry
    // that silently holds findings.
    $this->artisan('cbox-id:doctor')
        ->expectsOutputToContain('Deployment claims a shape it cannot serve')
        ->expectsOutputToContain('Set the account host.')
        ->assertExitCode(1);
});
