<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientSecretRefusal;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\ClientSecretRefused;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\StoredClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * A client may hold several live secrets, so a rotation can overlap.
 *
 * It could not. One `secret_hash` per client meant a rotation replaced the secret in the
 * same write that minted the new one, and every deployment still holding the old secret
 * failed on its next token request. The console called the operation "overlap-rotate".
 */
function secretRotationToken(TestCase $test, Client $client, string $secret): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client_id,
        'client_secret' => $secret,
    ]);
}

function secretRotationRegistry(): ClientRegistry
{
    return app(ClientRegistry::class);
}

it('stores a registered secret as a hash with a hint, and nothing else', function (): void {
    $registered = $this->makeClient();
    $secret = (string) $registered->secret;

    $rows = StoredClientSecret::query()->where('oauth_client_id', $registered->client->id)->get();

    expect($rows)->toHaveCount(1)
        ->and($rows[0]->secret_hash)->toBe(ClientSecret::hash($secret))
        ->and($rows[0]->hint)->toBe(substr($secret, -4))
        ->and($rows[0]->expires_at)->toBeNull()
        ->and($secret)->toStartWith('csec_')
        // The row never serializes its verifier.
        ->and($rows[0]->toArray())->not->toHaveKey('secret_hash');
});

it('keeps the old secret working through the grace period, and not a second longer', function (): void {
    // Frozen to a whole second: expiries are stored to the second, so a clock left
    // running would put the boundary wherever the test happened to be when it crossed it.
    $this->freezeSecond();

    $registered = $this->makeClient();
    $old = (string) $registered->secret;

    $rotated = secretRotationRegistry()->rotateSecret($registered->client, 3600);

    expect($rotated->secret)->not->toBe($old)
        ->and($rotated->previousExpireAt)->not->toBeNull();

    // Both work during the overlap — the whole point.
    secretRotationToken($this, $registered->client, $old)->assertOk();
    secretRotationToken($this, $registered->client, $rotated->secret)->assertOk();

    $this->travel(3599)->seconds();
    secretRotationToken($this, $registered->client, $old)->assertOk();

    $this->travel(2)->seconds();
    secretRotationToken($this, $registered->client, $old)->assertStatus(401)->assertJsonPath('error', 'invalid_client');
    secretRotationToken($this, $registered->client, $rotated->secret)->assertOk();
});

it('cuts the old secret off at once when the grace period is zero', function (): void {
    $registered = $this->makeClient();
    $old = (string) $registered->secret;

    $rotated = secretRotationRegistry()->rotateSecret($registered->client, 0);

    secretRotationToken($this, $registered->client, $old)->assertStatus(401);
    secretRotationToken($this, $registered->client, $rotated->secret)->assertOk();

    // And the dead row is gone rather than left to be compared forever.
    expect(secretRotationRegistry()->secrets($registered->client))->toHaveCount(1);
});

it('never extends a secret that was already on its way out', function (): void {
    // Frozen to a whole second: expiries are stored to the second, so a clock left
    // running would put the boundary wherever the test happened to be when it crossed it.
    $this->freezeSecond();

    $registered = $this->makeClient();
    $first = (string) $registered->secret;

    secretRotationRegistry()->rotateSecret($registered->client, 600);
    $second = secretRotationRegistry()->rotateSecret($registered->client, 7200);

    $this->travel(601)->seconds();

    // The first secret was due to expire in ten minutes; a later rotation with a longer
    // grace must not have handed it two more hours.
    secretRotationToken($this, $registered->client, $first)->assertStatus(401);
    secretRotationToken($this, $registered->client, $second->secret)->assertOk();
});

it('never accepts an expired secret, even one still on file', function (): void {
    $registered = $this->makeClient();
    $secret = (string) $registered->secret;

    // Past its expiry but not yet pruned — only a rotation prunes. The comparison must
    // look at `expires_at`, not at whether the row exists.
    StoredClientSecret::query()->where('oauth_client_id', $registered->client->id)
        ->update(['expires_at' => now()->subSecond()]);

    expect(secretRotationRegistry()->verifySecret($registered->client, $secret))->toBeFalse()
        ->and(secretRotationRegistry()->hasSecret($registered->client))->toBeFalse();

    secretRotationToken($this, $registered->client, $secret)->assertStatus(401);
});

it('refuses a wrong secret while several are live', function (): void {
    $registered = $this->makeClient();
    secretRotationRegistry()->rotateSecret($registered->client, 3600);

    expect(secretRotationRegistry()->verifySecret($registered->client, 'csec_'.str_repeat('0', 64)))->toBeFalse()
        ->and(secretRotationRegistry()->verifySecret($registered->client, ''))->toBeFalse();
});

it('lists the live secrets newest first, with hints and no hashes', function (): void {
    $registered = $this->makeClient();
    $rotated = secretRotationRegistry()->rotateSecret($registered->client, 3600);

    $secrets = secretRotationRegistry()->secrets($registered->client);

    expect($secrets)->toHaveCount(2)
        ->and($secrets[0]->id)->toBe($rotated->summary->id)
        ->and($secrets[0]->hint)->toBe(substr($rotated->secret, -4))
        ->and($secrets[0]->isExpiring())->toBeFalse()
        ->and($secrets[1]->hint)->toBe(substr((string) $registered->secret, -4))
        ->and($secrets[1]->isExpiring())->toBeTrue()
        ->and(get_object_vars($secrets[0]))->not->toHaveKey('secretHash');
});

it('keeps the deprecated secret_hash column equal to the newest live secret', function (): void {
    $registered = $this->makeClient();
    $rotated = secretRotationRegistry()->rotateSecret($registered->client, 3600);

    expect(Client::query()->whereKey($registered->client->id)->value('secret_hash'))->toBe(ClientSecret::hash($rotated->secret))
        ->and($registered->client->secret_hash)->toBe(ClientSecret::hash($rotated->secret));
});

it('refuses to rotate a public client', function (): void {
    $public = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code']);

    try {
        secretRotationRegistry()->rotateSecret($public->client);
        $this->fail('a public client was given a secret');
    } catch (ClientSecretRefused $e) {
        expect($e->reason)->toBe(ClientSecretRefusal::PublicClient);
    }

    expect(secretRotationRegistry()->hasSecret($public->client))->toBeFalse();
});

it('refuses to give a private_key_jwt client a bearer secret', function (): void {
    $registered = secretRotationRegistry()->register(new NewClient(
        name: 'Signer',
        jwks: ['keys' => [['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB', 'kid' => 'k1']]],
    ));

    try {
        secretRotationRegistry()->rotateSecret($registered->client);
        $this->fail('an asymmetric-only client was given a bearer secret');
    } catch (ClientSecretRefused $e) {
        expect($e->reason)->toBe(ClientSecretRefusal::SignsAssertions);
    }

    expect(secretRotationRegistry()->hasSecret($registered->client))->toBeFalse();
});

it('refuses a grace period outside its bounds', function (int $grace): void {
    config()->set('cbox-id.oauth.client_secrets.max_rotation_grace', 86400);
    $registered = $this->makeClient();

    try {
        secretRotationRegistry()->rotateSecret($registered->client, $grace);
        $this->fail("a grace of {$grace}s was accepted");
    } catch (ClientSecretRefused $e) {
        expect($e->reason)->toBe(ClientSecretRefusal::GraceOutOfRange);
    }

    // Refused BEFORE anything was written.
    expect(secretRotationRegistry()->secrets($registered->client))->toHaveCount(1);
})->with([-1, 86401]);

it('revokes one secret at once and leaves the others working', function (): void {
    $registered = $this->makeClient();
    $old = (string) $registered->secret;
    $rotated = secretRotationRegistry()->rotateSecret($registered->client, 3600);

    $oldId = secretRotationRegistry()->secrets($registered->client)[1]->id;
    secretRotationRegistry()->revokeSecret($registered->client, $oldId);

    secretRotationToken($this, $registered->client, $old)->assertStatus(401);
    secretRotationToken($this, $registered->client, $rotated->secret)->assertOk();
});

it('refuses to revoke the last live secret of a shared-secret client', function (): void {
    $registered = $this->makeClient();
    $only = secretRotationRegistry()->secrets($registered->client)[0]->id;

    try {
        secretRotationRegistry()->revokeSecret($registered->client, $only);
        $this->fail('the last secret was revoked');
    } catch (ClientSecretRefused $e) {
        expect($e->reason)->toBe(ClientSecretRefusal::LastLiveSecret);
    }

    secretRotationToken($this, $registered->client, (string) $registered->secret)->assertOk();
});

/**
 * The secret id must be bound to the client IN THE QUERY. Proven with environment scoping
 * suspended, so the environment scope cannot be what refuses it: both clients live in the
 * same environment here anyway, which is the case the binding exists for.
 */
it('will not revoke another client\'s secret by its id', function (): void {
    $mine = $this->makeClient();
    secretRotationRegistry()->rotateSecret($mine->client, 3600);

    $theirs = $this->makeClient();
    $theirSecretId = secretRotationRegistry()->secrets($theirs->client)[0]->id;

    $this->withoutEnvironmentScope(function () use ($mine, $theirSecretId): void {
        try {
            secretRotationRegistry()->revokeSecret($mine->client, $theirSecretId);
            $this->fail("another client's secret was revoked");
        } catch (ClientSecretRefused $e) {
            expect($e->reason)->toBe(ClientSecretRefusal::UnknownSecret);
        }
    });

    secretRotationToken($this, $theirs->client, (string) $theirs->secret)->assertOk();
});

it('stamps last_used_at on use, at most once a minute', function (): void {
    // Frozen to a whole second: expiries are stored to the second, so a clock left
    // running would put the boundary wherever the test happened to be when it crossed it.
    $this->freezeSecond();

    $registered = $this->makeClient();
    $secret = (string) $registered->secret;
    $row = fn (): StoredClientSecret => StoredClientSecret::query()->where('oauth_client_id', $registered->client->id)->firstOrFail();

    expect($row()->last_used_at)->toBeNull();

    secretRotationRegistry()->verifySecret($registered->client, $secret);
    $first = $row()->last_used_at;

    expect($first)->not->toBeNull();

    $this->travel(30)->seconds();
    secretRotationRegistry()->verifySecret($registered->client, $secret);
    expect($row()->last_used_at?->getTimestamp())->toBe($first?->getTimestamp());

    $this->travel(31)->seconds();
    secretRotationRegistry()->verifySecret($registered->client, $secret);
    expect($row()->last_used_at?->getTimestamp())->toBeGreaterThan((int) $first?->getTimestamp());
});

/**
 * Code built against 1.18 rotates by assigning `secret_hash` and saving. Ignoring that
 * would make its rotation silently inert: the new secret refused, the old one still
 * working. It keeps the meaning it had — the written hash is the one secret, at once.
 */
it('adopts a secret written straight to the deprecated column', function (): void {
    $registered = $this->makeClient();
    $old = (string) $registered->secret;
    secretRotationRegistry()->rotateSecret($registered->client, 3600);

    $new = 'csec_'.bin2hex(random_bytes(32));
    $client = Client::query()->findOrFail($registered->client->id);
    $client->secret_hash = hash('sha256', $new);
    $client->save();

    secretRotationToken($this, $client, $new)->assertOk();
    secretRotationToken($this, $client, $old)->assertStatus(401);
    expect(secretRotationRegistry()->secrets($client))->toHaveCount(1);

    $client->secret_hash = null;
    $client->save();

    expect(secretRotationRegistry()->hasSecret($client))->toBeFalse();
});

it('removes the secrets with the client', function (): void {
    $registered = $this->makeClient();
    secretRotationRegistry()->rotateSecret($registered->client, 3600);

    secretRotationRegistry()->delete($registered->client);

    expect(StoredClientSecret::query()->where('oauth_client_id', $registered->client->id)->count())->toBe(0);
});

it('audits every step of the lifecycle, with the actor who asked', function (): void {
    $org = $this->makeOrganization();
    $audit = $this->fakeAudit();
    $actor = AuditActor::organizationMember('usr_admin');

    $registered = secretRotationRegistry()->register(new NewClient(name: 'Billing', organizationId: $org->id), $actor);
    $client = $registered->client;

    secretRotationRegistry()->update($client, secretRotationRegistry()->blueprint($client)->withName('Billing v2'), $actor);
    $rotated = secretRotationRegistry()->rotateSecret($client, 60, $actor);
    secretRotationRegistry()->revokeSecret($client, secretRotationRegistry()->secrets($client)[1]->id, $actor);
    secretRotationRegistry()->delete($client, $actor);

    $actions = array_map(fn (AuditEvent $e): string => $e->action, $audit->recorded);

    expect($actions)->toBe(['app.created', 'app.updated', 'app.secret_rotated', 'app.secret_revoked', 'app.deleted']);

    foreach ($audit->recorded as $event) {
        expect($event->actorType)->toBe(ActorType::OrganizationMember)
            ->and($event->actorId)->toBe('usr_admin')
            // On the owning organization's trail, so the tenant can read it.
            ->and($event->organizationId)->toBe($org->id)
            ->and($event->targetType)->toBe('client')
            ->and($event->targetId)->toBe($client->client_id);
    }

    expect($audit->recorded[1]->context['changes'])->toBe(['name' => ['from' => 'Billing', 'to' => 'Billing v2']])
        ->and($audit->recorded[2]->context['hint'])->toBe(substr($rotated->secret, -4))
        // A secret's plaintext and hash never reach the trail.
        ->and(json_encode($audit->recorded))->not->toContain($rotated->secret)
        ->and(json_encode($audit->recorded))->not->toContain(ClientSecret::hash($rotated->secret));
});

it('records the system as the actor when none is given', function (): void {
    $audit = $this->fakeAudit();

    $this->makeClient();

    expect($audit->recorded)->toHaveCount(1)
        ->and($audit->recorded[0]->actorType)->toBe(ActorType::System)
        ->and($audit->recorded[0]->organizationId)->toBeNull();
});

it('records no update when nothing changed', function (): void {
    $registered = $this->makeClient();
    $audit = $this->fakeAudit();

    secretRotationRegistry()->update($registered->client, secretRotationRegistry()->blueprint($registered->client));

    expect($audit->recorded)->toBe([]);
});
