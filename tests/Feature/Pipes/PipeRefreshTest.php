<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Enums\PipeConnectionStatus;
use Cbox\Id\Pipes\Exceptions\PipeReauthorizationRequired;
use Cbox\Id\Pipes\Exceptions\PipeRefreshFailed;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;

uses(RefreshDatabase::class);

const PIPE_HUBSPOT_TOKEN_URL = 'https://api.hubapi.com/oauth/v1/token';

beforeEach(function (): void {
    /** A granted HubSpot connection whose access token expires in `$expiresIn` seconds. */
    $this->hubspotConnection = function (int $expiresIn = 30, string $user = 'user_1'): PipeConnection {
        $pipe = app(Pipes::class)->forProvider('hubspot') ?? $this->configurePipe('hubspot');
        app(Pipes::class)->grant($pipe->id, 'cid_app');

        return $this->connectPipeAccount('hubspot', $user, ['access_token' => 'access-1', 'refresh_token' => 'refresh-1', 'expires_in' => $expiresIn]);
    };
});

it('refreshes an expiring token before leasing it, and rotates a new refresh token', function (): void {
    $connection = ($this->hubspotConnection)();
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['access_token' => 'access-2', 'refresh_token' => 'refresh-2', 'expires_in' => 1800])]);

    $token = app(PipeTokens::class)->lease('hubspot', 'user_1', 'cid_app', 'sync-contacts');

    expect($token->accessToken)->toBe('access-2')
        ->and($token->expiresAt?->getTimestamp())->toBeGreaterThan(now()->addSeconds(1700)->getTimestamp());

    Http::assertSent(fn (Request $r): bool => $r->url() === PIPE_HUBSPOT_TOKEN_URL
        && $r['grant_type'] === 'refresh_token'
        && $r['refresh_token'] === 'refresh-1'
        && $r['client_secret'] === 'pipe-client-secret');

    $connection->refresh();
    expect(app(PipeSecrets::class)->open((string) $connection->refresh_secret_id, 'user_1', 't'))->toBe('refresh-2')
        ->and($connection->last_refreshed_at)->not->toBeNull()
        ->and($connection->refresh_failures)->toBe(0);
});

it('does not refresh a token that still has life in it', function (): void {
    ($this->hubspotConnection)(expiresIn: 1800);
    Http::fake();

    expect(app(PipeTokens::class)->lease('hubspot', 'user_1', 'cid_app', 'x')->accessToken)->toBe('access-1');

    Http::assertNothingSent();
});

it('keeps the refresh token when the provider does not rotate it', function (): void {
    $connection = ($this->hubspotConnection)();
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['access_token' => 'access-2', 'expires_in' => 1800])]);

    app(PipeTokens::class)->refresh($connection->id, force: true);

    expect(app(PipeSecrets::class)->open((string) $connection->refresh_secret_id, 'user_1', 't'))->toBe('refresh-1');
});

it('marks the connection needs_reauth and emits the event when the provider refuses the refresh token', function (string $provider, array $refusal, int $status): void {
    $events = $this->fakeEvents();
    $this->configurePipe($provider);
    app(Pipes::class)->grant(app(Pipes::class)->forProvider($provider)->id, 'cid_app');
    $connection = $this->connectPipeAccount($provider, 'user_1', $provider === 'slack'
        ? ['ok' => true, 'authed_user' => ['access_token' => 'a', 'refresh_token' => 'r', 'expires_in' => 10]]
        : ['access_token' => 'a', 'refresh_token' => 'r', 'expires_in' => 10]);
    Http::fake(['*' => Http::response($refusal, $status)]);

    $after = app(PipeTokens::class)->refresh($connection->id, force: true);

    expect($after->status)->toBe(PipeConnectionStatus::NeedsReauth)
        ->and($after->reauth_reason)->toBe($refusal['error'] ?? $refusal['status']);

    $emitted = array_values(array_filter($events->emitted, fn (DomainEvent $e): bool => $e->type === 'pipe.connection.needs_reauth'));
    expect($emitted)->toHaveCount(1)
        ->and($emitted[0]->payload)->toBe([
            'connection_id' => $connection->id,
            'user_id' => 'user_1',
            'provider' => $provider,
            'reason' => $refusal['error'] ?? $refusal['status'],
        ]);

    // And the app is told to send the person back through consent.
    expect(fn () => app(PipeTokens::class)->lease($provider, 'user_1', 'cid_app', 'x'))->toThrow(PipeReauthorizationRequired::class);
})->with([
    'Google invalid_grant' => ['google', ['error' => 'invalid_grant', 'error_description' => 'Token has been expired or revoked.'], 400],
    'Microsoft invalid_grant' => ['microsoft', ['error' => 'invalid_grant', 'error_description' => 'AADSTS70008'], 400],
    'Slack ok:false (200)' => ['slack', ['ok' => false, 'error' => 'invalid_refresh_token'], 200],
    'HubSpot BAD_REFRESH_TOKEN' => ['hubspot', ['status' => 'BAD_REFRESH_TOKEN', 'message' => 'missing or unknown refresh token'], 400],
    'Salesforce invalid_grant' => ['salesforce', ['error' => 'invalid_grant', 'error_description' => 'expired access/refresh token'], 400],
    'Linear invalid_grant' => ['linear', ['error' => 'invalid_grant'], 400],
    'GitHub bad_refresh_token (200)' => ['github', ['error' => 'bad_refresh_token'], 200],
]);

it('treats an outage as transient: the connection stays active, the failure is counted', function (int $status): void {
    $connection = ($this->hubspotConnection)(expiresIn: 1800);
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['message' => 'down'], $status)]);

    expect(fn () => app(PipeTokens::class)->refresh($connection->id, force: true))->toThrow(PipeRefreshFailed::class);

    $connection->refresh();
    expect($connection->status)->toBe(PipeConnectionStatus::Active)
        ->and($connection->refresh_failures)->toBe(1)
        ->and($connection->last_error)->toBe('provider_unavailable')
        ->and($connection->refresh_claimed_until)->toBeNull();
})->with([503, 429, 500]);

it('does not blame the person for a bad client secret', function (): void {
    $connection = ($this->hubspotConnection)(expiresIn: 1800);
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['error' => 'invalid_client'], 401)]);

    expect(fn () => app(PipeTokens::class)->refresh($connection->id, force: true))->toThrow(PipeRefreshFailed::class);

    expect($connection->fresh()?->status)->toBe(PipeConnectionStatus::Active)
        ->and($connection->fresh()?->last_error)->toBe('invalid_client');
});

it('is single-flight: a refresh another process holds is never repeated by the sweep', function (): void {
    $connection = ($this->hubspotConnection)();
    $connection->forceFill(['refresh_claimed_until' => now()->addSeconds(30)])->save();
    Http::fake();

    $after = app(PipeTokens::class)->refreshIfExpiring($connection->id, 600);

    Http::assertNothingSent();
    expect($after->last_refreshed_at)->toBeNull();
});

it('is single-flight: a lease that finds a refresh in progress waits for it and uses its result', function (): void {
    $connection = ($this->hubspotConnection)();
    $connection->forceFill(['refresh_claimed_until' => now()->addSeconds(30)])->save();
    Http::fake();

    // The "other process": while this one sleeps, it finishes its refresh and stores the
    // new token, then lets go of the claim.
    Sleep::fake();
    Sleep::whenFakingSleep(function () use ($connection): void {
        app(PipeSecrets::class)->rotate($connection->access_secret_id, 'user_1', 'access-from-the-other-process');
        PipeConnection::query()->whereKey($connection->id)->update([
            'access_expires_at' => now()->addSeconds(1800),
            'refresh_claimed_until' => null,
        ]);
    });

    $token = app(PipeTokens::class)->lease('hubspot', 'user_1', 'cid_app', 'x');

    expect($token->accessToken)->toBe('access-from-the-other-process');
    // The refresh token was spent once, by the other process — never here.
    Http::assertNothingSent();
});

it('gives up waiting rather than double-spending the refresh token', function (): void {
    config(['cbox-id.pipes.refresh_wait_milliseconds' => 1]);
    $connection = ($this->hubspotConnection)();
    $connection->forceFill(['refresh_claimed_until' => now()->addSeconds(30)])->save();
    Http::fake();
    Sleep::fake();

    expect(fn () => app(PipeTokens::class)->lease('hubspot', 'user_1', 'cid_app', 'x'))
        ->toThrow(fn (PipeRefreshFailed $e) => expect($e->reason)->toBe('refresh_in_progress'));

    Http::assertNothingSent();
});

it('reclaims a refresh claim whose holder died', function (): void {
    $connection = ($this->hubspotConnection)();
    $connection->forceFill(['refresh_claimed_until' => now()->subSecond()])->save();
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['access_token' => 'access-2', 'expires_in' => 1800])]);

    expect(app(PipeTokens::class)->lease('hubspot', 'user_1', 'cid_app', 'x')->accessToken)->toBe('access-2');
});

it('does not refresh twice when a second caller arrives after the first finished', function (): void {
    $connection = ($this->hubspotConnection)();
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['access_token' => 'access-2', 'expires_in' => 1800])]);

    app(PipeTokens::class)->refresh($connection->id);
    app(PipeTokens::class)->refresh($connection->id);

    Http::assertSentCount(1);
});

it('marks an expired connection with nothing to refresh as needs_reauth', function (): void {
    $this->configurePipe('github');
    $connection = $this->connectPipeAccount('github', 'user_1', ['access_token' => 'ghu_x', 'expires_in' => 28800]);
    $connection->forceFill(['access_expires_at' => now()->subMinute()])->save();
    Http::fake();

    expect(app(PipeTokens::class)->refresh($connection->id)->status)->toBe(PipeConnectionStatus::NeedsReauth)
        ->and($connection->fresh()?->reauth_reason)->toBe('no_refresh_token');
    Http::assertNothingSent();
});

it('sweeps every environment from the scheduler, each connection inside its own', function (): void {
    $a = ($this->hubspotConnection)(expiresIn: 120);
    $this->actingAsEnvironment('env_other');
    $b = ($this->hubspotConnection)(expiresIn: 120, user: 'user_2');
    $fresh = ($this->hubspotConnection)(expiresIn: 7200, user: 'user_3');
    app(EnvironmentContext::class)->set(null);

    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['access_token' => 'swept', 'expires_in' => 1800])]);

    $this->artisan('cbox-id:pipes:refresh')->assertSuccessful();

    Http::assertSentCount(2);

    $this->actingAsEnvironment('env_test');
    expect($a->fresh()?->last_refreshed_at)->not->toBeNull();
    $this->actingAsEnvironment('env_other');
    expect($b->fresh()?->last_refreshed_at)->not->toBeNull()
        ->and($fresh->fresh()?->last_refreshed_at)->toBeNull();
});

it('schedules the sweep', function (): void {
    $events = collect(app(Schedule::class)->events())
        ->filter(fn ($event): bool => str_contains((string) $event->command, 'cbox-id:pipes:refresh'));

    expect($events)->toHaveCount(1)
        ->and($events->first()->expression)->toBe('*/5 * * * *');
});

it('audits refreshes without the token values', function (): void {
    $this->fakeAudit();
    $connection = ($this->hubspotConnection)();
    Http::fake([PIPE_HUBSPOT_TOKEN_URL => Http::response(['access_token' => 'access-SECRET-2', 'refresh_token' => 'refresh-SECRET-2', 'expires_in' => 1800])]);

    app(PipeTokens::class)->refresh($connection->id, force: true);

    $audit = app(AuditLog::class);
    $audit->assertRecorded('pipe.connection.refreshed');
    expect(json_encode($audit->recorded))->not->toContain('SECRET')->not->toContain('access-1')->not->toContain('refresh-1');
});
