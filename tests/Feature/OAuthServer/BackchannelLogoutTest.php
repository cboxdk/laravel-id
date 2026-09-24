<?php

declare(strict_types=1);

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SignedInSession;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Crypto\ValueObjects\TokenClaims;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Maintenance\Enums\PrunableTable;
use Cbox\Id\Maintenance\Pruner;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\LogoutTokenIssuer;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Jobs\DeliverBackchannelLogout;
use Cbox\Id\OAuthServer\JwtLogoutTokenIssuer;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\Models\SessionParticipant;
use Cbox\Id\OAuthServer\Support\SessionIdentifier;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\GuardPolicy;
use Cbox\Ssrf\Testing\FakeResolver;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * OpenID Connect Back-Channel Logout 1.0.
 *
 * WHY THIS FILE EXISTS. When a person signed out of Cbox ID — or an administrator ended
 * their sessions, or removed their access — every application that had signed them in
 * kept its own session until it expired. Nothing told it. Consumers compensated by
 * re-checking the person's grants on every request.
 */

const BCL_URI = 'https://rp.example/backchannel-logout';
const BCL_VERIFIER = 'a-sufficiently-long-code-verifier-1234567890';

/**
 * @param  list<string>  $scopes
 */
function bclClient(?string $uri = BCL_URI, bool $sessionRequired = false, array $scopes = ['openid', 'offline_access']): Client
{
    return app(ClientRegistry::class)->register(new NewClient(
        'RP with back-channel logout',
        ClientType::Public,
        redirectUris: ['https://app.test/cb'],
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: $scopes,
        backchannelLogoutUri: $uri,
        backchannelLogoutSessionRequired: $sessionRequired,
    ))->client;
}

/**
 * Sign a person in to a client the way the host does it: a code minted from their
 * session, redeemed at the token endpoint.
 *
 * @param  list<string>  $scopes
 */
function bclSignIn(object $test, Client $client, string $userId, ?string $sessionId, ?string $organizationId = 'org_a', array $scopes = ['openid', 'offline_access']): TestResponse
{
    $code = app(AuthorizationCodes::class)->issue(
        $client->client_id,
        $userId,
        $organizationId,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', BCL_VERIFIER, true)),
        'S256',
        'nonce-from-the-authorize-request',
        time(),
        ['pwd'],
        sessionId: $sessionId,
    );

    return $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client_id,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => BCL_VERIFIER,
    ])->assertOk();
}

function bclSession(string $userId, ?string $organizationId = 'org_a'): string
{
    return app(SessionManager::class)->start($userId, $organizationId, ['pwd'])->id;
}

function bclClaims(string $jwt): TokenClaims
{
    return app(TokenSigner::class)->verify($jwt, [SigningAlg::RS256]);
}

/**
 * @return array<string, mixed>
 */
function bclSegment(string $jwt, int $index): array
{
    $decoded = json_decode(Base64Url::decode(explode('.', $jwt)[$index]), true);

    return is_array($decoded) ? $decoded : [];
}

function bclEnvironment(): string
{
    return (string) app(EnvironmentContext::class)->current()?->environmentKey();
}

/** Fixed DNS for the SSRF guard, so no test touches the network. */
function bclDns(array $table): void
{
    app()->instance(Resolver::class, new FakeResolver($table));
    app()->forgetInstance(GuardPolicy::class);
    app()->forgetInstance(UrlGuard::class);
}

/**
 * @return list<DeliverBackchannelLogout>
 */
function bclQueued(): array
{
    return Queue::pushed(DeliverBackchannelLogout::class)->values()->all();
}

// ---------------------------------------------------------------------------------------
// sid on the ID Token, and the record of who to tell
// ---------------------------------------------------------------------------------------

it('puts sid on the ID Token — derived from the session, never the session id itself', function (): void {
    $client = bclClient();
    $session = bclSession('user_42');

    $claims = bclClaims(bclSignIn($this, $client, 'user_42', $session)->json('id_token'));

    expect($claims->get('sid'))->toBe(SessionIdentifier::sid($session))
        // The raw id is the host's row key and dates the session; every RP sees this value.
        ->and($claims->get('sid'))->not->toBe($session)
        ->and(str_contains((string) $claims->get('sid'), $session))->toBeFalse();
})->group('security');

it('keeps the same sid on a refreshed ID Token', function (): void {
    $client = bclClient();
    $session = bclSession('user_42');

    $first = bclSignIn($this, $client, 'user_42', $session);

    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client_id,
        'refresh_token' => $first->json('refresh_token'),
    ])->assertOk();

    expect(bclClaims($refreshed->json('id_token'))->get('sid'))->toBe(SessionIdentifier::sid($session));
});

it('carries no sid when the host did not name a session, rather than inventing one', function (): void {
    $client = bclClient();

    $claims = bclClaims(bclSignIn($this, $client, 'user_42', null)->json('id_token'));

    expect($claims->has('sid'))->toBeFalse()
        ->and(SessionParticipant::query()->count())->toBe(0);
});

it('records the session against the client once, however many codes it redeems', function (): void {
    $client = bclClient();
    $session = bclSession('user_42');

    bclSignIn($this, $client, 'user_42', $session);
    bclSignIn($this, $client, 'user_42', $session);

    $rows = SessionParticipant::query()->get();

    expect($rows)->toHaveCount(1)
        ->and($rows[0]->session_id)->toBe($session)
        ->and($rows[0]->client_id)->toBe($client->client_id)
        ->and($rows[0]->user_id)->toBe('user_42')
        ->and($rows[0]->organization_id)->toBe('org_a')
        ->and($rows[0]->ended_at)->toBeNull();
});

it('advertises back-channel logout and the sid claim in discovery', function (): void {
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('backchannel_logout_supported', true)
        ->assertJsonPath('backchannel_logout_session_supported', true)
        ->assertJsonPath('claims_supported', fn (array $claims): bool => in_array('sid', $claims, true));
});

// ---------------------------------------------------------------------------------------
// The logout token (§2.4)
// ---------------------------------------------------------------------------------------

it('mints a logout token with exactly the claims §2.4 requires, and no nonce', function (): void {
    $client = bclClient();

    $token = app(LogoutTokenIssuer::class)->issue($client, new LogoutNotice($client->client_id, 'user_42', 'the-sid'));

    $header = bclSegment($token, 0);
    $payload = bclSegment($token, 1);
    $claims = bclClaims($token);

    expect($header['typ'] ?? null)->toBe('logout+jwt')
        ->and($header['alg'] ?? null)->toBe('RS256')
        ->and($claims->get('iss'))->toBe(ServerMetadata::issuer())
        ->and($claims->get('aud'))->toBe($client->client_id)
        ->and($claims->get('sub'))->toBe('user_42')
        ->and($claims->get('sid'))->toBe('the-sid')
        ->and($claims->get('jti'))->toBeString()->not->toBe('')
        ->and($claims->get('iat'))->toBeInt()
        // "Short": two minutes, so a replay window is the delivery window.
        ->and((int) $claims->get('exp') - (int) $claims->get('iat'))->toBeLessThanOrEqual(120)->toBeGreaterThan(0)
        // §2.4: a logout token MUST NOT contain a nonce.
        ->and(array_key_exists('nonce', $payload))->toBeFalse()
        ->and(array_keys($payload))->toEqualCanonicalizing(['iss', 'aud', 'iat', 'exp', 'jti', 'events', 'sub', 'sid']);

    // The member is an empty JSON OBJECT. PHP's `[]` would encode as `[]`, which a strict
    // relying party rejects — so this reads the wire bytes, not a decoded array.
    $json = Base64Url::decode(explode('.', $token)[1]);

    expect($json)->toContain('"events":{"http://schemas.openid.net/event/backchannel-logout":{}}');
});

it('mints a fresh jti every time, so a retried delivery is not refused as a replay', function (): void {
    $client = bclClient();
    $notice = new LogoutNotice($client->client_id, 'user_42');

    $one = bclClaims(app(LogoutTokenIssuer::class)->issue($client, $notice));
    $two = bclClaims(app(LogoutTokenIssuer::class)->issue($client, $notice));

    expect($one->get('jti'))->not->toBe($two->get('jti'))
        ->and($one->has('sid'))->toBeFalse();
});

it('validates as a relying party would — against the published JWKS', function (): void {
    $client = bclClient();

    $token = app(LogoutTokenIssuer::class)->issue($client, new LogoutNotice($client->client_id, null, 'the-sid'));

    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json();

    // §2.6 step 3: validate exactly as an ID Token — iss, aud, signature, iat.
    $decoded = (array) JWT::decode($token, JWK::parseKeySet($jwks, 'RS256'));

    expect($decoded['iss'])->toBe(ServerMetadata::issuer())
        ->and($decoded['aud'])->toBe($client->client_id)
        ->and($decoded['sid'])->toBe('the-sid')
        ->and(array_key_exists('sub', $decoded))->toBeFalse()
        ->and((array) $decoded['events'])->toHaveKey(JwtLogoutTokenIssuer::EVENT);
});

it('refuses to build a notice that could only produce a token with neither sub nor sid', function (): void {
    expect(fn () => new LogoutNotice('cid_x', null, null))
        ->toThrow(InvalidArgumentException::class, 'needs a subject, a sid, or both');
});

// ---------------------------------------------------------------------------------------
// Delivery (§2.5): queued, SSRF-guarded, retried
// ---------------------------------------------------------------------------------------

it('POSTs the token as a form to the registered URI and records the delivery', function (): void {
    bclDns(['rp.example' => ['93.184.216.34']]);
    Http::fake(['rp.example/*' => Http::response('', 200)]);
    $client = bclClient();

    DeliverBackchannelLogout::dispatchSync(bclEnvironment(), $client->client_id, 'user_42', 'the-sid');

    Http::assertSent(function (Request $request) use ($client): bool {
        $claims = bclClaims((string) $request['logout_token']);

        return $request->url() === BCL_URI
            && $request->method() === 'POST'
            && $request->isForm()
            && $claims->get('aud') === $client->client_id
            && $claims->get('sid') === 'the-sid';
    });

    $entry = AuditEntry::query()->where('action', 'oauth.backchannel_logout.delivered')->sole();

    expect($entry->target_id)->toBe('user_42')
        ->and($entry->context['client_id'] ?? null)->toBe($client->client_id);
});

it('accepts 204 as done — some frameworks answer that for 200 (§2.8)', function (): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response('', 204)]);
    $client = bclClient();

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    $job->assertNotReleased();
    $job->assertNotFailed();
});

it('delivers from a worker that carries no environment, as the one the logout happened in', function (): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response('', 200)]);
    $client = bclClient();
    $environment = bclEnvironment();
    $issuer = ServerMetadata::issuer();

    // A queue worker has no ambient environment; the client row, the key and the issuer
    // are all environment-owned, so the job has to re-enter the right one itself.
    app(EnvironmentContext::class)->set(null);

    DeliverBackchannelLogout::dispatchSync($environment, $client->client_id, 'user_42', null);

    $sent = Http::recorded()->map(fn (array $pair): string => (string) $pair[0]['logout_token'])->all();

    // Verified back inside the environment: the key it was signed with is that one's.
    $this->actingAsEnvironment($environment);

    expect($sent)->toHaveCount(1)
        ->and(bclClaims($sent[0])->get('iss'))->toBe($issuer)
        ->and(bclClaims($sent[0])->get('aud'))->toBe($client->client_id);
});

it('refuses to call a URI that resolves to a private or metadata address', function (string $uri, array $dns): void {
    // The guard ON — its default — and nothing on the wire.
    config(['cbox-id.oauth.backchannel_logout.verify_url' => true]);
    bclDns($dns);
    Http::fake();
    $client = bclClient($uri);

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    Http::assertNothingSent();
    // Final, not retried: the address will not become public by waiting.
    $job->assertFailed();
    $job->assertNotReleased();

    $entry = AuditEntry::query()->where('action', 'oauth.backchannel_logout.failed')->sole();

    expect((string) ($entry->context['reason'] ?? ''))->toContain('refused by the SSRF guard');
})->with([
    'cloud metadata literal' => ['https://169.254.169.254/latest/meta-data', []],
    'loopback literal' => ['https://127.0.0.1/logout', []],
    'a name that resolves inside' => ['https://rp.internal/logout', ['rp.internal' => ['10.0.0.5']]],
])->group('security');

it('retries a relying party that is down, with a growing delay', function (int $status): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response('', $status)]);
    $client = bclClient();

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    $job->assertReleased(10);
    $job->assertNotFailed();

    $second = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    $second->job->attempts = 2;
    app()->call([$second, 'handle']);

    $second->assertReleased(60);
    expect(AuditEntry::query()->where('action', 'like', 'oauth.backchannel_logout.%')->count())->toBe(0);
})->with([500, 503, 408, 429]);

it('retries a connection that fails', function (): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(fn () => throw new ConnectionException('Connection timed out'));
    $client = bclClient();

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    $job->assertReleased(10);
});

it('gives up after the last attempt and records why', function (): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response('', 503)]);
    $client = bclClient();

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', 'the-sid'))->withFakeQueueInteractions();
    $job->job->attempts = DeliverBackchannelLogout::maxAttempts();
    app()->call([$job, 'handle']);

    $job->assertNotReleased();
    $job->assertFailed();

    $entry = AuditEntry::query()->where('action', 'oauth.backchannel_logout.failed')->sole();

    expect($entry->context['reason'] ?? null)->toBe('HTTP 503')
        ->and($entry->context['sid'] ?? null)->toBe('the-sid')
        ->and($entry->context['attempts'] ?? null)->toBe(DeliverBackchannelLogout::maxAttempts());
});

it('does not retry a token the relying party refused', function (): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response(['error' => 'invalid_request'], 400)]);
    $client = bclClient();

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    $job->assertNotReleased();
    $job->assertFailed();

    expect(AuditEntry::query()->where('action', 'oauth.backchannel_logout.failed')->sole()->context['reason'] ?? null)
        ->toBe('HTTP 400: invalid_request');
});

it('never sends a sid-less token to a client that registered session_required', function (): void {
    config(['cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake();
    $client = bclClient(sessionRequired: true);

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    Http::assertNothingSent();
    $job->assertFailed();
});

it('skips, quietly, a client that removed its URI after the logout was queued', function (): void {
    Http::fake();
    $client = bclClient();
    app(ClientRegistry::class)->configureBackchannelLogout($client, null);

    $job = (new DeliverBackchannelLogout(bclEnvironment(), $client->client_id, 'user_42', null))->withFakeQueueInteractions();
    app()->call([$job, 'handle']);

    Http::assertNothingSent();
    $job->assertNotFailed();
    $job->assertNotReleased();
});

it('keeps sign-out working on the sync queue when a relying party is down', function (): void {
    // `sync` runs the job inside the request that queued it. A throw there would have
    // turned "sign out" into an error page because some application returned 500.
    config(['queue.default' => 'sync', 'cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response('', 500)]);
    $client = bclClient();
    $session = bclSession('user_42');
    bclSignIn($this, $client, 'user_42', $session);

    app(SessionManager::class)->revoke($session);

    Http::assertSentCount(1);
    expect(app(SessionManager::class)->active($session))->toBeNull();
});

it('tells nobody when the sign-out it belongs to rolls back', function (): void {
    config(['queue.default' => 'sync', 'cbox-id.oauth.backchannel_logout.verify_url' => false]);
    Http::fake(['rp.example/*' => Http::response('', 200)]);
    $client = bclClient();
    $session = bclSession('user_42');
    bclSignIn($this, $client, 'user_42', $session);

    try {
        DB::transaction(function () use ($session): void {
            app(SessionManager::class)->revoke($session);

            throw new RuntimeException('the surrounding work failed');
        });
    } catch (RuntimeException) {
        // The point of the test.
    }

    Http::assertNothingSent();
});

// ---------------------------------------------------------------------------------------
// What triggers it
// ---------------------------------------------------------------------------------------

it('tells every client the session signed the person in to when that session ends', function (): void {
    Queue::fake();
    $notified = bclClient();
    $silent = bclClient(uri: null);
    $session = bclSession('user_42');
    bclSignIn($this, $notified, 'user_42', $session);
    bclSignIn($this, $silent, 'user_42', $session);

    app(SessionManager::class)->revoke($session);

    $jobs = bclQueued();

    expect($jobs)->toHaveCount(1)
        ->and($jobs[0]->clientId)->toBe($notified->client_id)
        ->and($jobs[0]->subject)->toBe('user_42')
        ->and($jobs[0]->sid)->toBe(SessionIdentifier::sid($session))
        ->and($jobs[0]->environmentId)->toBe(bclEnvironment())
        ->and(SessionParticipant::query()->whereNull('ended_at')->count())->toBe(0);

    // At-least-once upstream: ending it again tells nobody twice.
    app(SessionManager::class)->revoke($session);
    app(SessionManager::class)->revokeAllForUser('user_42');

    expect(bclQueued())->toHaveCount(1);
});

it('does not tell a client about a session it was never signed in from', function (): void {
    Queue::fake();
    $client = bclClient();
    $mine = bclSession('user_42');
    $other = bclSession('user_42');
    bclSignIn($this, $client, 'user_42', $mine);

    app(SessionManager::class)->revoke($other);

    expect(bclQueued())->toBe([]);
});

it('signs the person out of every app on "sign out everywhere", by sub — or by sid where required', function (): void {
    Queue::fake();
    $bySubject = bclClient();
    $bySession = bclClient(sessionRequired: true);
    $laptop = bclSession('user_42');
    $phone = bclSession('user_42');

    foreach ([$laptop, $phone] as $session) {
        bclSignIn($this, $bySubject, 'user_42', $session);
        bclSignIn($this, $bySession, 'user_42', $session);
    }

    app(SessionManager::class)->revokeAllForUser('user_42');

    $jobs = collect(bclQueued());
    $subjectOnly = $jobs->where('clientId', $bySubject->client_id)->values();
    $perSession = $jobs->where('clientId', $bySession->client_id)->values();

    // One sub-only token means "every session of this person" (§2.4) — one is enough.
    expect($subjectOnly)->toHaveCount(1)
        ->and($subjectOnly[0]->subject)->toBe('user_42')
        ->and($subjectOnly[0]->sid)->toBeNull()
        // An RP that asked for sid gets one token per session, each naming it.
        ->and($perSession->pluck('sid')->all())->toEqualCanonicalizing([
            SessionIdentifier::sid($laptop),
            SessionIdentifier::sid($phone),
        ]);
});

it('reaches the apps when an administrator signs a user out through the session manager', function (): void {
    Queue::fake();
    $client = bclClient();
    $subject = $this->makeUser('dana@example.test');
    $session = bclSession($subject->id);
    bclSignIn($this, $client, $subject->id, $session);

    // Deprovisioning revokes the person's grants — refresh tokens and access tokens —
    // and the apps those grants signed them in to have to hear about it.
    app(Subjects::class)->deactivate($subject->id);

    expect(collect(bclQueued())->pluck('subject')->all())->toBe([$subject->id]);
});

it('withdraws only one organization\'s sessions when grants are revoked in that organization', function (): void {
    Queue::fake();
    $client = bclClient();
    $inA = bclSession('user_42', 'org_a');
    $inB = bclSession('user_42', 'org_b');
    bclSignIn($this, $client, 'user_42', $inA, 'org_a');
    bclSignIn($this, $client, 'user_42', $inB, 'org_b');

    $revoked = app(RefreshTokens::class)->withdrawAccess('user_42', 'org_a');

    $jobs = bclQueued();

    expect($revoked)->toBe(1)
        ->and($jobs)->toHaveCount(1)
        // By sid, so the app session in org_b survives: a sub-only token would end it too.
        ->and($jobs[0]->sid)->toBe(SessionIdentifier::sid($inA))
        ->and(SessionParticipant::query()->where('session_id', $inB)->value('ended_at'))->toBeNull();
});

it('reaches a client that holds a grant but was never recorded against a session', function (): void {
    Queue::fake();
    $client = bclClient();
    // A refresh token from a code the host minted without naming the session.
    bclSignIn($this, $client, 'user_42', null);

    app(RefreshTokens::class)->withdrawAccess('user_42');

    $jobs = bclQueued();

    expect($jobs)->toHaveCount(1)
        ->and($jobs[0]->subject)->toBe('user_42')
        ->and($jobs[0]->sid)->toBeNull();
});

it('signs nobody out when grants are only revoked to refresh claims', function (): void {
    Queue::fake();
    $client = bclClient();
    $session = bclSession('user_42', 'org_a');
    bclSignIn($this, $client, 'user_42', $session, 'org_a');

    // What a host does on every role assignment and unassignment: revoke the refresh
    // tokens so the next one carries the new roles. The person has not lost access, so no
    // application may be told to end their session — that would sign everybody out of
    // everything whenever an administrator touched a role.
    $revoked = app(RefreshTokens::class)->revokeForUser('user_42', 'org_a');

    expect($revoked)->toBe(1)
        ->and(bclQueued())->toBe([])
        ->and(SessionParticipant::query()->where('session_id', $session)->value('ended_at'))->toBeNull()
        ->and(RefreshToken::query()->where('user_id', 'user_42')->whereNull('revoked_at')->count())->toBe(0);
});

it('tells only the one app a person disconnects', function (): void {
    Queue::fake();
    $kept = bclClient();
    $dropped = bclClient();
    $session = bclSession('user_42');
    bclSignIn($this, $kept, 'user_42', $session);
    bclSignIn($this, $dropped, 'user_42', $session);

    app(RefreshTokens::class)->revokeForUserAndClient('user_42', $dropped->client_id);

    expect(collect(bclQueued())->pluck('clientId')->all())->toBe([$dropped->client_id])
        ->and(RefreshToken::query()->where('client_id', $kept->client_id)->whereNull('revoked_at')->count())->toBe(1);
});

it('withdraws access when a person is removed from an organization', function (string $type): void {
    Queue::fake();
    $client = bclClient();
    $inA = bclSession('user_42', 'org_a');
    $inB = bclSession('user_42', 'org_b');
    bclSignIn($this, $client, 'user_42', $inA, 'org_a');
    bclSignIn($this, $client, 'user_42', $inB, 'org_b');

    $event = (new Event)->forceFill([
        'id' => 'evt_1',
        'type' => $type,
        'organization_id' => 'org_a',
        'payload' => ['user_id' => 'user_42'],
    ]);

    event(new EventDelivered($event));

    $jobs = bclQueued();

    expect($jobs)->toHaveCount(1)
        ->and($jobs[0]->sid)->toBe(SessionIdentifier::sid($inA))
        ->and(RefreshToken::query()->where('organization_id', 'org_a')->whereNull('revoked_at')->count())->toBe(0)
        ->and(RefreshToken::query()->where('organization_id', 'org_b')->whereNull('revoked_at')->count())->toBe(1);
})->with(['organization.member_removed', 'membership.deleted']);

it('ignores a removal event that names no organization, rather than signing the person out of all of them', function (): void {
    Queue::fake();
    $client = bclClient();
    bclSignIn($this, $client, 'user_42', bclSession('user_42'));

    event(new EventDelivered((new Event)->forceFill([
        'id' => 'evt_2',
        'type' => 'organization.member_removed',
        'organization_id' => null,
        'payload' => ['user_id' => 'user_42'],
    ])));

    expect(bclQueued())->toBe([]);
});

it('notifies the apps on RP-initiated logout with a verified hint', function (): void {
    Queue::fake();
    $client = bclClient();
    $subject = $this->makeUser('erin@example.test');
    $session = bclSession($subject->id);
    $idToken = bclSignIn($this, $client, $subject->id, $session)->json('id_token');

    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/oauth/logout?'.http_build_query(['id_token_hint' => $idToken]))
        ->assertOk();

    expect(collect(bclQueued())->pluck('subject')->all())->toBe([$subject->id]);
});

it('ends THIS browser\'s session on an unverified logout when the host says which it is', function (): void {
    Queue::fake();
    $client = bclClient();
    $subject = $this->makeUser('fay@example.test');
    $here = bclSession($subject->id);
    $elsewhere = bclSession($subject->id);
    bclSignIn($this, $client, $subject->id, $here);
    bclSignIn($this, $client, $subject->id, $elsewhere);

    app()->instance(SignedInSession::class, new class($here) implements SignedInSession
    {
        public function __construct(private readonly string $session) {}

        public function id(): ?string
        {
            return $this->session;
        }
    });

    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/oauth/logout')
        ->assertOk();

    $sessions = app(SessionManager::class);

    // This browser, and nothing else — an unproven request still cannot sign the person
    // out of their other devices.
    expect($sessions->active($here))->toBeNull()
        ->and($sessions->active($elsewhere))->not->toBeNull()
        ->and(collect(bclQueued())->pluck('sid')->all())->toBe([SessionIdentifier::sid($here)]);
})->group('security');

it('ends no session on an unverified logout when the host does not say which is this browser\'s', function (): void {
    Queue::fake();
    $client = bclClient();
    $subject = $this->makeUser('gus@example.test');
    $session = bclSession($subject->id);
    bclSignIn($this, $client, $subject->id, $session);

    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/oauth/logout')
        ->assertOk();

    expect(app(SessionManager::class)->active($session))->not->toBeNull()
        ->and(bclQueued())->toBe([]);
});

// ---------------------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------------------

it('prunes a participation once its session can no longer end, and keeps a live one', function (): void {
    $client = bclClient();
    $live = bclSession('user_42');
    $gone = bclSession('user_42');
    $recent = bclSession('user_42');
    bclSignIn($this, $client, 'user_42', $live);
    bclSignIn($this, $client, 'user_42', $gone);
    bclSignIn($this, $client, 'user_42', $recent);

    $old = now()->subDays(40);

    // Ended long ago.
    SessionParticipant::query()->where('session_id', $recent)->update(['ended_at' => $old]);
    // Old, and its session row has been pruned away.
    SessionParticipant::query()->where('session_id', $gone)->update(['created_at' => $old]);
    DB::table('auth_sessions')->where('id', $gone)->delete();
    // Old, but its session is alive — must stay.
    SessionParticipant::query()->where('session_id', $live)->update(['created_at' => $old]);

    app(Pruner::class)->prune(PrunableTable::OauthSessionParticipants);

    expect(SessionParticipant::query()->pluck('session_id')->all())->toBe([$live]);
});
