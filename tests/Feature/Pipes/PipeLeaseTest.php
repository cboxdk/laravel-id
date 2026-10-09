<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Exceptions\PipeConnectionMissing;
use Cbox\Id\Pipes\Exceptions\PipeConnectionNotFound;
use Cbox\Id\Pipes\Exceptions\PipeLeaseDenied;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

uses(RefreshDatabase::class);
uses()->group('isolation');

beforeEach(function (): void {
    $this->pipe = $this->configurePipe('salesforce');
    $this->grantPipe($this->pipe, 'cid_granted');
    $this->connection = $this->connectPipeAccount('salesforce', 'user_1', [
        'access_token' => '00D!LEASE-ME',
        'refresh_token' => '5Aep-NEVER-LEAVES',
        'instance_url' => 'https://acme.my.salesforce.com',
    ]);
});

it('leases a working token to an app granted the pipe, with what it needs to call the API', function (): void {
    $token = app(PipeTokens::class)->lease('salesforce', 'user_1', 'cid_granted', 'sync-accounts');

    expect($token->accessToken)->toBe('00D!LEASE-ME')
        ->and($token->tokenType)->toBe('Bearer')
        ->and($token->connectionId)->toBe($this->connection->id)
        ->and($token->metadata['instance_url'])->toBe('https://acme.my.salesforce.com')
        ->and($token->leaseExpiresAt->getTimestamp())->toBeLessThanOrEqual(now()->addSeconds(300)->getTimestamp());

    // Audited twice: by Pipes, with the app as the actor — and by the vault, whose lease
    // names the app in its purpose.
    $leased = AuditEntry::query()->where('action', 'pipe.token.leased')->sole();
    expect($leased->actor_id)->toBe('cid_granted')
        ->and($leased->context['purpose'] ?? null)->toBe('sync-accounts');

    $vaultLease = AuditEntry::query()->where('action', 'vault.secret.leased')->where('target_id', $this->connection->access_secret_id)->latest('id')->first();
    expect($vaultLease?->actor_id)->toBe(PipeSecrets::BROKER_CLIENT_ID)
        ->and($vaultLease?->context['purpose'] ?? null)->toBe('pipe:cid_granted:sync-accounts');
});

it('refuses an app that is not granted the pipe — uniformly, whatever the reason', function (): void {
    $refusals = [];

    foreach ([
        ['salesforce', 'cid_not_granted'],   // no grant
        ['github', 'cid_granted'],           // no such pipe
        ['nonsense', 'cid_granted'],         // no such provider
        ['salesforce', ''],                  // no client at all
    ] as [$provider, $client]) {
        try {
            app(PipeTokens::class)->lease($provider, 'user_1', $client, 'probe');
        } catch (PipeLeaseDenied $e) {
            $refusals[] = $e->getMessage();
        }
    }

    app(Pipes::class)->update($this->pipe->id, enabled: false);

    try {
        app(PipeTokens::class)->lease('salesforce', 'user_1', 'cid_granted', 'probe');
    } catch (PipeLeaseDenied $e) {
        $refusals[] = $e->getMessage();
    }

    expect($refusals)->toHaveCount(5)
        ->and(array_unique($refusals))->toBe(['Lease denied.']);

    // The reason is on the trail, not in the answer.
    expect(AuditEntry::query()->where('action', 'pipe.lease.denied')->pluck('context')->map(fn ($c) => $c['reason'])->all())
        ->toBe(['no_grant', 'unknown_pipe', 'unknown_pipe', 'no_grant', 'pipe_disabled']);
});

it('tells a granted app the person has not connected — and an ungranted one nothing', function (): void {
    expect(fn () => app(PipeTokens::class)->lease('salesforce', 'user_without_connection', 'cid_granted', 'x'))
        ->toThrow(PipeConnectionMissing::class)
        ->and(fn () => app(PipeTokens::class)->lease('salesforce', 'user_without_connection', 'cid_other', 'x'))
        ->toThrow(PipeLeaseDenied::class);
});

it('stops leasing the moment the app\'s grant is revoked', function (): void {
    app(Pipes::class)->revokeGrant($this->pipe->id, 'cid_granted');

    expect(fn () => app(PipeTokens::class)->lease('salesforce', 'user_1', 'cid_granted', 'x'))->toThrow(PipeLeaseDenied::class);
});

it('never lets the refresh token out, and keeps the person\'s tokens out of the vault API\'s reach', function (): void {
    $vault = app(SecretVault::class);

    // An app cannot lease either secret directly from the vault: it has no grant there.
    expect(fn () => $vault->lease($this->connection->access_secret_id, 'cid_granted', 'x', VaultOwner::user('user_1')))->toThrow(LeaseDenied::class)
        ->and(fn () => $vault->lease((string) $this->connection->refresh_secret_id, 'cid_granted', 'x', VaultOwner::user('user_1')))->toThrow(LeaseDenied::class);

    // And the vault's organization-/environment-scoped management paths cannot see them.
    expect(fn () => $vault->grant($this->connection->access_secret_id, 'cid_granted', null))->toThrow(SecretNotFound::class)
        ->and(fn () => $vault->grant($this->connection->access_secret_id, 'cid_granted', VaultOwner::organization('org_x')))->toThrow(SecretNotFound::class);

    expect(json_encode($this->connection->toArray()))->not->toContain('secret_id');
});

it('isolates environments: another environment\'s app, pipe and connection are invisible', function (): void {
    $this->actingAsEnvironment('env_other');

    // The same provider, the same client id, the same user id — none of it reaches
    // across. An app in env_other granted ITS own pipe gets nothing from env_test.
    $mirror = app(Pipes::class)->configure('salesforce', 'x', 'y');
    app(Pipes::class)->grant($mirror->id, 'cid_granted');

    expect(fn () => app(PipeTokens::class)->lease('salesforce', 'user_1', 'cid_granted', 'x'))->toThrow(PipeConnectionMissing::class)
        ->and(app(PipeConnections::class)->find($this->connection->id))->toBeNull()
        ->and(app(PipeConnections::class)->forUser('user_1'))->toBe([])
        ->and(fn () => app(PipeConnections::class)->disconnect($this->connection->id))->toThrow(PipeConnectionNotFound::class)
        ->and(fn () => app(PipeTokens::class)->refresh($this->connection->id))->toThrow(PipeConnectionNotFound::class);

    $this->actingAsEnvironment('env_test');
    expect(app(PipeConnections::class)->find($this->connection->id))->not->toBeNull();
});

it('keeps one person out of another\'s connections', function (): void {
    expect(app(PipeConnections::class)->find($this->connection->id, 'user_2'))->toBeNull()
        ->and(fn () => app(PipeConnections::class)->disconnect($this->connection->id, 'user_2'))->toThrow(PipeConnectionNotFound::class)
        ->and(app(PipeConnections::class)->forUser('user_2'))->toBe([]);
});

it('never writes a token or the client secret to the audit trail, the event outbox or the log', function (): void {
    $logged = [];
    Event::listen(MessageLogged::class, function (MessageLogged $m) use (&$logged): void {
        $logged[] = $m->message.json_encode($m->context);
    });

    app(PipeTokens::class)->lease('salesforce', 'user_1', 'cid_granted', 'x');
    try {
        app(PipeTokens::class)->lease('salesforce', 'user_1', 'cid_denied', 'x');
    } catch (PipeLeaseDenied) {
    }
    app(PipeConnections::class)->disconnect($this->connection->id, 'user_1');

    $everything = json_encode(DB::table('audit_logs')->get()).json_encode(DB::table('events')->get()).implode("\n", $logged);

    expect($everything)->not->toContain('LEASE-ME')
        ->not->toContain('NEVER-LEAVES')
        ->not->toContain('pipe-client-secret');
});
