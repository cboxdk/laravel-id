<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\SupportSessions;
use Cbox\Id\OAuthServer\Contracts\TokenExchange;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantType;
use Cbox\Id\OAuthServer\Enums\SupportActorKind;
use Cbox\Id\OAuthServer\Enums\SupportSessionRefusal;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\Exceptions\SupportSessionRefused;
use Cbox\Id\OAuthServer\Models\AuthorizationCode;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\SupportSession;
use Cbox\Id\OAuthServer\ValueObjects\ActingParty;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\NewSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\StartedSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\SupportCodeRequest;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * SUPPORT SESSIONS: the vendor's staff signing in to ONE app AS a customer's user.
 *
 * The app completes an ordinary code exchange. What must hold, whatever path a code or
 * token takes afterwards: every token names the real actor (`act`), none can be renewed,
 * none outlives the session, and ending the session kills what it issued. Who may start
 * one is the other half — the app's own `support:impersonate`, held environment-wide.
 */

const SUPPORT_VERIFIER = 'support-session-code-verifier-0123456789abcdef';
const SUPPORT_REDIRECT = 'https://cadastre.test/cb';

function supportApp(bool $firstParty = true, ?string $organizationId = null, string $name = 'Cadastre'): Client
{
    return app(ClientRegistry::class)->register(new NewClient(
        $name,
        ClientType::Public,
        redirectUris: [SUPPORT_REDIRECT],
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'offline_access'],
        firstParty: $firstParty,
        organizationId: $organizationId,
    ))->client;
}

/**
 * The customer, their member, and a staff person holding the app's `support:impersonate`
 * environment-wide.
 *
 * @return array{0: Client, 1: Organization}
 */
function supportWorld(): array
{
    $client = supportApp();
    $organization = app(Organizations::class)->create(new NewOrganization('Acme', 'acme-'.bin2hex(random_bytes(3))));
    app(Memberships::class)->add($organization->id, 'customer-1', MembershipRole::Member);

    grantSupport('staff-1', $client->client_id);

    return [$client, $organization];
}

function grantSupport(string $userId, string $clientId): void
{
    $roles = app(Roles::class);
    $role = $roles->define(null, 'Support', clientId: $clientId, tenantAssignable: false);
    // grantPermission() resolves the permission within the ROLE's scope — so this is the
    // app's own declaration of `support:impersonate`, as a manifest would make it.
    $roles->grantPermission(null, $role->id, 'support:impersonate');
    $roles->assignEverywhere($userId, $role->id);
}

function supportRequest(Client $client, Organization $organization, array $overrides = []): NewSupportSession
{
    return new NewSupportSession(...array_merge([
        'actorId' => 'staff-1',
        'actorKind' => SupportActorKind::Staff,
        'targetUserId' => 'customer-1',
        'organizationId' => $organization->id,
        'clientId' => $client->client_id,
        'reason' => 'Ticket 4411: invoice totals look wrong',
        'scopes' => ['openid', 'profile', 'offline_access'],
    ], $overrides));
}

function supportCode(?string $nonce = 'n-1'): SupportCodeRequest
{
    return new SupportCodeRequest(SUPPORT_REDIRECT, Base64Url::encode(hash('sha256', SUPPORT_VERIFIER, true)), $nonce);
}

function redeemSupportCode(object $test, Client $client, string $code): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client_id,
        'code' => $code,
        'redirect_uri' => SUPPORT_REDIRECT,
        'code_verifier' => SUPPORT_VERIFIER,
    ]);
}

/** @return array<string, mixed> */
function verifiedClaims(string $jwt): array
{
    return app(TokenSigner::class)->verify($jwt, [SigningAlg::RS256])->all();
}

function supportRefusalOf(Closure $attempt): ?SupportSessionRefusal
{
    try {
        $attempt();
    } catch (SupportSessionRefused $refused) {
        return $refused->refusal;
    }

    return null;
}

it('mints tokens that name the actor, cannot be renewed and end with the session', function (): void {
    [$client, $organization] = supportWorld();

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization, ['ttlSeconds' => 600]), supportCode());

    expect($started->code)->toBeString();

    $response = redeemSupportCode($this, $client, (string) $started->code)->assertOk();

    // No refresh token, even though the app is registered for offline_access and asked
    // for it: the session never carries the scope, so no token claims to have it.
    expect($started->session->scopes)->toBe(['openid', 'profile'])
        ->and($response->json('refresh_token'))->toBeNull()
        ->and($response->json('expires_in'))->toBeLessThanOrEqual(600);

    $access = verifiedClaims($response->json('access_token'));

    expect($access['scope'])->toBe('openid profile');
    $id = verifiedClaims($response->json('id_token'));
    $sessionEnd = $started->session->expires_at->getTimestamp();

    expect($access['sub'])->toBe('customer-1')
        ->and((array) $access['act'])->toBe(['sub' => 'staff-1'])
        ->and($access['org'])->toBe($organization->id)
        ->and($access['exp'])->toBeLessThanOrEqual($sessionEnd)
        ->and($id['sub'])->toBe('customer-1')
        ->and((array) $id['act'])->toBe(['sub' => 'staff-1'])
        ->and($id['exp'])->toBeLessThanOrEqual($sessionEnd)
        ->and($id['nonce'])->toBe('n-1')
        // Nobody authenticated as the customer, so no login is asserted.
        ->and($id)->not->toHaveKey('auth_time')
        ->and($id)->not->toHaveKey('acr');
});

it('tells an introspecting resource server who is acting', function (): void {
    [, $organization] = supportWorld();
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'Cadastre API',
        ClientType::Confidential,
        redirectUris: [SUPPORT_REDIRECT],
        grantTypes: ['authorization_code'],
        scopes: ['openid'],
        firstParty: true,
    ));
    $client = $registered->client;
    grantSupport('staff-1', $client->client_id);

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization), supportCode());

    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client_id,
        'client_secret' => $registered->secret,
        'code' => $started->code,
        'redirect_uri' => SUPPORT_REDIRECT,
        'code_verifier' => SUPPORT_VERIFIER,
    ])->assertOk()->json('access_token');

    $this->postJson('/oauth/introspect', [
        'token' => $token,
        'client_id' => $client->client_id,
        'client_secret' => $registered->secret,
    ])->assertJsonPath('active', true)
        ->assertJsonPath('sub', 'customer-1')
        ->assertJsonPath('act.sub', 'staff-1');
});

it('caps every token at the session’s end, not the client’s lifetime', function (): void {
    [$client, $organization] = supportWorld();

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization, ['ttlSeconds' => 120]), supportCode());

    $response = redeemSupportCode($this, $client, (string) $started->code)->assertOk();

    // The deployment default is 900 seconds; the session has two minutes left.
    expect($response->json('expires_in'))->toBeLessThanOrEqual(120)
        ->and(verifiedClaims($response->json('id_token'))['exp'])->toBeLessThanOrEqual($started->session->expires_at->getTimestamp());
});

it('audits both sides and tells the customer', function (): void {
    [$client, $organization] = supportWorld();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    app()->forgetInstance(SupportSessions::class);

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization));

    $events->assertEmitted(WebhookEventType::SupportSessionStarted->value, fn ($event): bool => $event->organizationId === $organization->id
        && $event->payload['actor_id'] === 'staff-1'
        && $event->payload['user_id'] === 'customer-1'
        && $event->payload['client_id'] === $client->client_id
        && $event->payload['reason'] === 'Ticket 4411: invoice totals look wrong');

    // The customer's trail (who acted as their member) and the environment's (what the
    // vendor's staff did) — two readers, two chains.
    $audit->assertRecorded('support_session.started', fn ($event): bool => $event->organizationId === $organization->id
        && $event->actorId === 'staff-1' && $event->targetId === 'customer-1');
    $audit->assertRecorded('support_session.started', fn ($event): bool => $event->organizationId === null
        && $event->context['support_session_id'] === $started->session->id);
});

/*
 * --------------------------------------------------------------------------
 * Who may start one
 * --------------------------------------------------------------------------
 */

it('refuses a session without a reason', function (): void {
    [$client, $organization] = supportWorld();

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['reason' => '   ']))))
        ->toBe(SupportSessionRefusal::ReasonRequired);
});

/**
 * @group security
 */
it('refuses staff who do not hold support:impersonate environment-wide', function (): void {
    [$client, $organization] = supportWorld();

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['actorId' => 'staff-2']))))
        ->toBe(SupportSessionRefusal::NotPermitted);

    expect(SupportSession::query()->count())->toBe(0);
})->group('security');

/**
 * @group security
 *
 * Holding the role inside ONE customer makes you that customer's support, not the
 * vendor's. It must not let you act as a member of every other customer.
 */
it('refuses staff who hold support:impersonate only inside one organization', function (): void {
    [$client, $organization] = supportWorld();
    $roles = app(Roles::class);
    $local = $roles->define(null, 'Local support', clientId: $client->client_id);
    $roles->grantPermission(null, $local->id, 'support:impersonate');
    $roles->assign($organization->id, 'staff-2', $local->id);

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['actorId' => 'staff-2']))))
        ->toBe(SupportSessionRefusal::NotPermitted);
})->group('security');

/**
 * @group security
 *
 * The app has to have declared the permission itself. Another app's support staff, or a
 * platform-wide permission that merely shares the name, is not this app opting in.
 */
it('refuses support:impersonate declared by another app or by nobody', function (): void {
    [$client, $organization] = supportWorld();
    $other = supportApp(name: 'Tax');

    grantSupport('staff-2', $other->client_id);

    $roles = app(Roles::class);
    $generic = $roles->define(null, 'Generic support');
    $roles->grantPermission(null, $generic->id, 'support:impersonate');
    $roles->assignEverywhere('staff-3', $generic->id);

    foreach (['staff-2', 'staff-3'] as $actor) {
        expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['actorId' => $actor]))))
            ->toBe(SupportSessionRefusal::NotPermitted);
    }
})->group('security');

it('lets an environment administrator start one on the caller’s word', function (): void {
    [$client, $organization] = supportWorld();

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization, [
        'actorId' => 'env-admin-1',
        'actorKind' => SupportActorKind::EnvironmentAdmin,
    ]));

    expect($started->session->actor_kind)->toBe(SupportActorKind::EnvironmentAdmin);
});

it('refuses acting as yourself', function (): void {
    [$client, $organization] = supportWorld();
    app(Memberships::class)->add($organization->id, 'staff-1', MembershipRole::Member);

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['targetUserId' => 'staff-1']))))
        ->toBe(SupportSessionRefusal::SelfImpersonation);
});

/**
 * @group security
 */
it('refuses a target who is not an active member of the organization', function (?MembershipStatus $status): void {
    [$client, $organization] = supportWorld();

    if ($status !== null) {
        app(Memberships::class)->add($organization->id, 'customer-2', MembershipRole::Member)
            ->forceFill(['status' => $status])->save();
    }

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['targetUserId' => 'customer-2']))))
        ->toBe(SupportSessionRefusal::TargetNotMember);
})->with(['not a member' => null, 'invited' => MembershipStatus::Invited, 'suspended' => MembershipStatus::Suspended])->group('security');

it('refuses a suspended organization', function (): void {
    [$client, $organization] = supportWorld();
    app(Organizations::class)->suspend($organization->id, 'operator');

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization))))
        ->toBe(SupportSessionRefusal::OrganizationInactive);
});

/**
 * @group security
 *
 * THE CONSENT DECISION. The customer never agrees to a support session, so its tokens may
 * go only to an app whose ordinary sign-in skips consent anyway. A third-party app, or one
 * a customer registered, would be handed the customer's data on somebody else's say-so.
 */
it('refuses an app that is not a first-party app of the environment', function (bool $firstParty, bool $customerOwned): void {
    [, $organization] = supportWorld();
    $app = supportApp($firstParty, $customerOwned ? $organization->id : null, 'Other');
    grantSupport('staff-9', $app->client_id);

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(supportRequest($app, $organization, ['actorId' => 'staff-9']))))
        ->toBe(SupportSessionRefusal::ClientNotEligible);
})->with([
    'third party' => [false, false],
    'customer-registered first party' => [true, true],
])->group('security');

/**
 * @group security
 *
 * A code is handed to whoever controls the redirect URI, so it goes only to a registered
 * one — and a refused code leaves no session behind that the customer was told about.
 */
it('refuses an unregistered redirect URI and records nothing', function (): void {
    [$client, $organization] = supportWorld();

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->begin(
        supportRequest($client, $organization),
        new SupportCodeRequest('https://evil.test/cb', Base64Url::encode(hash('sha256', SUPPORT_VERIFIER, true))),
    )))->toBe(SupportSessionRefusal::RedirectUriNotRegistered);

    expect(SupportSession::query()->count())->toBe(0);
})->group('security');

it('never lets a session outlive the configured maximum, nor an hour', function (int|string $configured, ?int $requested, int $expected): void {
    $this->freezeSecond();
    config()->set('cbox-id.oauth.support_sessions.max_ttl', $configured);
    [$client, $organization] = supportWorld();

    $session = app(SupportSessions::class)->begin(supportRequest($client, $organization, ['ttlSeconds' => $requested]))->session;

    expect((int) round(now()->diffInSeconds($session->expires_at)))->toBe($expected);
})->with([
    'default' => [3600, null, 3600],
    'configured above an hour' => [7200, 7200, 3600],
    'configured lower' => [600, 3600, 600],
    'requested shorter' => [3600, 300, 300],
    'requested below a minute' => [3600, 5, 60],
]);

/*
 * --------------------------------------------------------------------------
 * After it starts
 * --------------------------------------------------------------------------
 */

/**
 * @group security
 *
 * Ending the session kills everything it issued: a code minted before, and every token.
 * The token endpoint re-reads the session rather than trusting the code.
 */
it('kills the session’s codes and tokens when it ends', function (): void {
    [$client, $organization] = supportWorld();
    $sessions = app(SupportSessions::class);

    $started = $sessions->begin(supportRequest($client, $organization), supportCode());
    $token = redeemSupportCode($this, $client, (string) $started->code)->assertOk()->json('access_token');
    $pending = $sessions->issueCode($started->session->id, 'staff-1', supportCode());

    $sessions->end($started->session->id, 'staff-1');

    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeFalse();

    redeemSupportCode($this, $client, $pending)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');

    expect(supportRefusalOf(fn () => $sessions->issueCode($started->session->id, 'staff-1', supportCode())))
        ->toBe(SupportSessionRefusal::SessionNotActive);
})->group('security');

/**
 * @group security
 *
 * The session re-read is its own guard, not a side effect of consuming codes on end():
 * a code whose session has expired is refused even though nothing touched the code.
 */
it('refuses a code whose session expired before it was redeemed', function (): void {
    [$client, $organization] = supportWorld();

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization, ['ttlSeconds' => 60]), supportCode());

    // Push the session's end into the past without touching the code row.
    SupportSession::query()->whereKey($started->session->id)->update(['expires_at' => now()->subSecond()]);

    redeemSupportCode($this, $client, (string) $started->code)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant')
        ->assertJsonPath('error_description', 'the support session this code was issued for has ended');
})->group('security');

/**
 * @group security
 */
it('mints further codes only for the session’s own actor', function (): void {
    [$client, $organization] = supportWorld();
    grantSupport('staff-2', $client->client_id);

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization));

    expect(supportRefusalOf(fn () => app(SupportSessions::class)->issueCode($started->session->id, 'staff-2', supportCode())))
        ->toBe(SupportSessionRefusal::SessionNotActive);

    expect(app(SupportSessions::class)->issueCode($started->session->id, 'staff-1', supportCode()))->toStartWith('ac_');
})->group('security');

/**
 * @group security
 *
 * Token exchange would mint a fresh token through the ordinary path — no `act`, a new
 * lifetime, exchangeable again before it expired: a refresh token by another name, and
 * one that tells the app the customer is signed in themselves.
 */
it('refuses to exchange an acted token', function (): void {
    [$client, $organization] = supportWorld();

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization), supportCode());
    $token = redeemSupportCode($this, $client, (string) $started->code)->assertOk()->json('access_token');

    expect(fn () => app(TokenExchange::class)->exchange($client, new TokenExchangeRequest(
        subjectToken: $token,
        subjectTokenType: TokenExchangeRequest::ACCESS_TOKEN_TYPE,
    )))->toThrow(InvalidTokenExchange::class, 'The subject token was issued to somebody acting for its subject (act) and cannot be exchanged.');
})->group('security');

/**
 * @group security
 *
 * The same refusal at the token endpoint, for a confidential app that HAS enabled the
 * token-exchange grant (1.19 app settings) and names its own registered API as the
 * resource (1.19 audience resolver). The grant toggle is checked first — an app without it
 * is refused before the subject token is read — and with it, the acted subject is refused
 * before any audience or scope is resolved for the new token.
 */
it('refuses an acted token at the token endpoint, whatever grants and APIs the app has', function (): void {
    $organization = app(Organizations::class)->create(new NewOrganization('Acme', 'acme-'.bin2hex(random_bytes(3))));
    app(Memberships::class)->add($organization->id, 'customer-1', MembershipRole::Member);

    $register = fn (array $grants): object => app(ClientRegistry::class)->register(new NewClient(
        'Cadastre',
        ClientType::Confidential,
        redirectUris: [SUPPORT_REDIRECT],
        grantTypes: $grants,
        scopes: ['openid', 'profile', 'parcels:read'],
        firstParty: true,
    ));

    $exchanger = $register(['authorization_code', GrantType::TokenExchange->value]);
    $plain = $register(['authorization_code']);
    $this->makeApi('https://parcels.example.test', ['parcels:read'], clientId: $exchanger->client->client_id);

    $actedFor = function (object $registered) use ($organization): string {
        grantSupport('staff-1', $registered->client->client_id);
        $started = app(SupportSessions::class)->begin(supportRequest($registered->client, $organization, ['scopes' => ['openid', 'parcels:read']]), supportCode());

        return $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $registered->client->client_id,
            'client_secret' => $registered->secret,
            'code' => $started->code,
            'redirect_uri' => SUPPORT_REDIRECT,
            'code_verifier' => SUPPORT_VERIFIER,
        ])->assertOk()->json('access_token');
    };

    $exchange = fn (object $registered, string $token) => $this->postJson('/oauth/token', [
        'grant_type' => GrantType::TokenExchange->value,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $token,
        'subject_token_type' => TokenExchangeRequest::ACCESS_TOKEN_TYPE,
        'resource' => 'https://parcels.example.test',
    ]);

    $exchange($exchanger, $actedFor($exchanger))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant')
        ->assertJsonPath('error_description', 'The subject token was issued to somebody acting for its subject (act) and cannot be exchanged.');

    $exchange($plain, $actedFor($plain))
        ->assertStatus(400)
        ->assertExactJson(['error' => 'unauthorized_client']);
})->group('security');

/**
 * @group security
 *
 * A half-written acting pair is not a code this package wrote; it is refused rather than
 * redeemed as an ordinary — unacted, refreshable — grant.
 */
it('refuses a code whose acting party is half written', function (): void {
    [$client, $organization] = supportWorld();

    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization), supportCode());
    AuthorizationCode::query()->where('support_session_id', $started->session->id)->update(['actor_id' => null]);

    redeemSupportCode($this, $client, (string) $started->code)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
})->group('security');

it('lists the actor’s open sessions', function (): void {
    [$client, $organization] = supportWorld();
    $sessions = app(SupportSessions::class);

    $first = $sessions->begin(supportRequest($client, $organization));
    $second = $sessions->begin(supportRequest($client, $organization));
    $sessions->end($first->session->id);

    expect(array_map(static fn (SupportSession $session): string => $session->id, $sessions->openFor('staff-1')))
        ->toBe([$second->session->id]);

    expect($second)->toBeInstanceOf(StartedSupportSession::class);
});

/**
 * @group security
 *
 * `act` is reserved: a token-minting hook can neither forge one onto an ordinary token
 * (making a customer's own sign-in look like staff) nor rewrite the one a support session
 * carries (hiding who really holds it).
 */
it('never lets a token hook forge or rewrite act', function (): void {
    [$client] = supportWorld();
    config()->set('cbox-id.external_actions.verify_url', false);
    $this->fakeActionTransport()->willEnrich(['act' => ['sub' => 'somebody-else']]);
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');

    $issuer = app(TokenIssuer::class);

    $ordinary = verifiedClaims($issuer->issueForUser($client, 'customer-1', null)->token);
    $acted = verifiedClaims($issuer->issueActing($client, 'customer-1', null, [], new ActingParty('staff-1', 'session-1'), now()->addMinutes(5))->token);

    expect($ordinary)->not->toHaveKey('act')
        ->and((array) $acted['act'])->toBe(['sub' => 'staff-1']);
})->group('security');

it('never claims offline_access on an acted token, even when the request was empty', function (): void {
    [$client] = supportWorld();

    $claims = verifiedClaims(app(TokenIssuer::class)->issueActing($client, 'customer-1', null, [], new ActingParty('staff-1', 'session-1'), now()->addMinutes(5))->token);

    expect(explode(' ', $claims['scope']))->toBe(['openid', 'profile']);
});

/*
 * THE SESSION SAYS WHAT ITS TOKENS CARRY. A session used to store the scopes it was asked
 * for (or the app's whole registration) narrowed only to that registration; every token
 * then went through the audience resolver, which drops a scope nobody registered once the
 * app's scopes include a registered API's. So the session, its codes and whatever reported
 * it listed `apps.manifest`, and no token carried it.
 */
it('stores exactly the scopes its tokens will carry', function (): void {
    $organization = app(Organizations::class)->create(new NewOrganization('Acme', 'acme-'.bin2hex(random_bytes(3))));
    app(Memberships::class)->add($organization->id, 'customer-1', MembershipRole::Member);

    $client = app(ClientRegistry::class)->register(new NewClient(
        'Cadastre',
        ClientType::Public,
        redirectUris: [SUPPORT_REDIRECT],
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'parcels:read', 'apps.manifest'],
        firstParty: true,
    ))->client;
    $this->makeApi('https://parcels.example.test', ['parcels:read'], clientId: $client->client_id);
    grantSupport('staff-1', $client->client_id);

    // Nothing asked for: the app's whole registration, settled to one audience.
    $started = app(SupportSessions::class)->begin(supportRequest($client, $organization, ['scopes' => []]), supportCode());

    expect($started->session->scopes)->toBe(['openid', 'profile', 'parcels:read']);

    $token = redeemSupportCode($this, $client, (string) $started->code)->assertOk();

    // The signed claim, not the response's `scope`: RFC 6749 §5.1 echoes that only when
    // the grant was narrowed, and nothing was — which is the point.
    expect(explode(' ', (string) verifiedClaims((string) $token->json('access_token'))['scope']))
        ->toBe($started->session->scopes);
});

it('refuses a session whose scopes span two APIs before anything is started', function (): void {
    $organization = app(Organizations::class)->create(new NewOrganization('Acme', 'acme-'.bin2hex(random_bytes(3))));
    app(Memberships::class)->add($organization->id, 'customer-1', MembershipRole::Member);

    $client = app(ClientRegistry::class)->register(new NewClient(
        'Cadastre',
        ClientType::Public,
        redirectUris: [SUPPORT_REDIRECT],
        grantTypes: ['authorization_code'],
        scopes: ['openid', 'parcels:read', 'tax:assess'],
        firstParty: true,
    ))->client;
    $this->makeApi('https://parcels.example.test', ['parcels:read']);
    $this->makeApi('https://tax.example.test', ['tax:assess']);
    grantSupport('staff-1', $client->client_id);

    expect(fn () => app(SupportSessions::class)->begin(supportRequest($client, $organization, ['scopes' => ['openid', 'parcels:read', 'tax:assess']]), supportCode()))
        ->toThrow(InvalidAudience::class);

    expect(SupportSession::query()->count())->toBe(0)
        ->and(AuthorizationCode::query()->count())->toBe(0);
});
