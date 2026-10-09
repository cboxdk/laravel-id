<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Exceptions\InvalidPipeConfiguration;
use Cbox\Id\Pipes\Exceptions\PipeNotFound;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.pipes.verify_url' => false]);
});

it('seals the client secret and never hands it back', function (): void {
    $pipe = app(Pipes::class)->configure('github', 'Iv1.abc', 'gh-client-secret-xyz', ['read:user', 'repo']);

    $raw = DB::table('pipes')->where('id', $pipe->id)->first();

    expect($raw->client_secret_encrypted)->not->toContain('gh-client-secret-xyz')
        ->and(json_encode($pipe->toArray()))->not->toContain('client_secret')
        ->and(app(PipeSecrets::class)->clientSecret($pipe->fresh()))->toBe('gh-client-secret-xyz')
        ->and($pipe->scopes)->toBe(['read:user', 'repo']);

    // Bound to the row: the same ciphertext does not open as another pipe's.
    $other = app(Pipes::class)->configure('google', 'g-client', 'g-secret');
    $other->client_secret_encrypted = $raw->client_secret_encrypted;

    expect(fn () => app(PipeSecrets::class)->clientSecret($other))->toThrow(DecryptionFailed::class);
});

it('registers the sealed client secret for the master-key rewrap', function (): void {
    $columns = array_map(fn ($c): string => $c->table.'.'.$c->column, app(SealedColumns::class)->all());

    expect($columns)->toContain('pipes.client_secret_encrypted');
});

it('names the field each refusal is about', function (string $provider, string $clientId, string $secret, ?array $scopes, array $parameters, string $field): void {
    expect(fn () => app(Pipes::class)->configure($provider, $clientId, $secret, $scopes, $parameters))
        ->toThrow(fn (InvalidPipeConfiguration $e) => expect($e->field)->toBe($field));
})->with([
    'unknown provider' => ['myspace', 'a', 'b', null, [], 'provider'],
    'blank client id' => ['github', ' ', 'b', null, [], 'client_id'],
    'blank secret' => ['github', 'a', '', null, [], 'client_secret'],
    'bad scope' => ['github', 'a', 'b', ['a b'], [], 'scopes'],
    'bad parameter' => ['salesforce', 'a', 'b', null, ['domain' => 'evil.test'], 'parameters'],
]);

it('uses the catalogue scopes when the pipe names none', function (): void {
    expect(app(Pipes::class)->configure('microsoft', 'ms', 'secret')->scopes)->toBe(['offline_access', 'User.Read']);
});

it('refuses an unknown provider, a duplicate, a blank credential and a malformed scope', function (): void {
    $pipes = app(Pipes::class);
    $pipes->configure('github', 'a', 'b');

    expect(fn () => $pipes->configure('myspace', 'a', 'b'))->toThrow(InvalidPipeConfiguration::class)
        ->and(fn () => $pipes->configure('github', 'a', 'b'))->toThrow(InvalidPipeConfiguration::class)
        ->and(fn () => $pipes->configure('google', '  ', 'b'))->toThrow(InvalidPipeConfiguration::class)
        ->and(fn () => $pipes->configure('google', 'a', ''))->toThrow(InvalidPipeConfiguration::class)
        ->and(fn () => $pipes->configure('google', 'a', 'b', ['openid email']))->toThrow(InvalidPipeConfiguration::class)
        ->and(fn () => $pipes->configure('google', 'a', 'b', ['x&prompt=none']))->not->toThrow(InvalidPipeConfiguration::class);
});

it('updates only what it is given, and audits the names of what changed — never the secret', function (): void {
    $this->fakeAudit();
    $pipes = app(Pipes::class);
    $pipe = $pipes->configure('github', 'a', 'old-secret');

    $updated = $pipes->update($pipe->id, clientSecret: 'new-secret-value', enabled: false);

    expect($updated->client_id)->toBe('a')
        ->and($updated->enabled)->toBeFalse()
        ->and(app(PipeSecrets::class)->clientSecret($updated))->toBe('new-secret-value');

    $audit = app(AuditLog::class);
    $audit->assertRecorded('pipe.updated', fn ($event): bool => $event->context['changed'] === ['client_secret', 'enabled']);
    expect(json_encode($audit->recorded))->not->toContain('new-secret-value')->not->toContain('old-secret');
});

it('grants and revokes apps idempotently', function (): void {
    $pipes = app(Pipes::class);
    $pipe = $pipes->configure('github', 'a', 'b');

    $pipes->grant($pipe->id, 'cid_one');
    $pipes->grant($pipe->id, 'cid_one');
    $pipes->grant($pipe->id, 'cid_two');

    expect($pipes->grantedClients($pipe->id))->toBe(['cid_one', 'cid_two'])
        ->and($pipes->isGranted($pipe->id, 'cid_one'))->toBeTrue();

    $pipes->revokeGrant($pipe->id, 'cid_one');
    $pipes->revokeGrant($pipe->id, 'cid_one');

    expect($pipes->grantedClients($pipe->id))->toBe(['cid_two'])
        ->and($pipes->isGranted($pipe->id, 'cid_one'))->toBeFalse()
        ->and(fn () => $pipes->grant('missing', 'cid_x'))->toThrow(PipeNotFound::class);
});

it('removing a pipe revokes every connection\'s tokens in the vault', function (): void {
    $pipe = $this->configurePipe('hubspot');
    $connection = $this->connectPipeAccount('hubspot', 'user_1', ['access_token' => 'hs-access', 'refresh_token' => 'hs-refresh', 'expires_in' => 1800]);

    app(Pipes::class)->remove($pipe->id);

    expect(Pipe::query()->count())->toBe(0)
        ->and(PipeConnection::query()->count())->toBe(0)
        ->and(VaultSecret::query()->whereKey($connection->access_secret_id)->first()?->isRevoked())->toBeTrue()
        ->and(VaultSecret::query()->whereKey($connection->refresh_secret_id)->first()?->isRevoked())->toBeTrue();
});

it('keeps pipes inside their environment', function (): void {
    $pipe = app(Pipes::class)->configure('github', 'a', 'b');

    $this->actingAsEnvironment('env_other');

    expect(app(Pipes::class)->find($pipe->id))->toBeNull()
        ->and(app(Pipes::class)->all())->toBe([])
        ->and(fn () => app(Pipes::class)->update($pipe->id, clientId: 'hijack'))->toThrow(PipeNotFound::class)
        ->and(fn () => app(Pipes::class)->grant($pipe->id, 'cid_attacker'))->toThrow(PipeNotFound::class)
        ->and(fn () => app(Pipes::class)->remove($pipe->id))->toThrow(PipeNotFound::class);

    // The other environment can configure the same provider for itself.
    expect(app(Pipes::class)->configure('github', 'mine', 'mine')->id)->not->toBe($pipe->id);
});

it('records the actor a console or an API passes, and the system otherwise', function (): void {
    $this->fakeAudit();
    $pipes = app(Pipes::class);

    $pipe = $pipes->configure('github', 'a', 'b', actor: AuditActor::user('admin_1'));
    $pipes->grant($pipe->id, 'cid_x', AuditActor::service('key_1'));
    $pipes->update($pipe->id, enabled: false);

    $audit = app(AuditLog::class);
    $audit->assertRecorded('pipe.configured', fn ($e): bool => $e->actorType === ActorType::User && $e->actorId === 'admin_1');
    $audit->assertRecorded('pipe.grant.created', fn ($e): bool => $e->actorType === ActorType::Service && $e->actorId === 'key_1');
    $audit->assertRecorded('pipe.updated', fn ($e): bool => $e->actorType === ActorType::System && $e->actorId === null);
});
