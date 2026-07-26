<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Enums\FailPolicy;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\ExternalActions\Payloads\RegistrationPayload;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(fn () => config()->set('cbox-id.external_actions.verify_url', false));

/** Queries issued while running a callback. */
function hookPointQueries(Closure $callback): int
{
    $count = 0;
    DB::listen(function () use (&$count): void {
        $count++;
    });

    $callback();

    return $count;
}

/** The payload the single recorded hook call carried. */
function sentPayload(object $transport): array
{
    expect($transport->sent)->toHaveCount(1);

    return $transport->sent[0]['context']->payload;
}

/*
|--------------------------------------------------------------------------
| post_login
|--------------------------------------------------------------------------
*/

it('consults the post-login hook before a session exists, telling it how the user authenticated', function (): void {
    $transport = $this->fakeActionTransport();
    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://risk.example.test');

    $session = app(SessionManager::class)->start('alice', 'org_x', ['pwd', 'mfa'], '203.0.113.7', 'curl/8.6');

    expect(sentPayload($transport))->toBe([
        'user_id' => 'alice',
        'organization_id' => 'org_x',
        'amr' => ['pwd', 'mfa'],
        'ip' => '203.0.113.7',
        'user_agent' => 'curl/8.6',
    ])->and($session->exists)->toBeTrue();
});

it('creates no session at all when a post-login hook denies', function (): void {
    $this->fakeActionTransport()->willDeny('device is not enrolled');
    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://risk.example.test');

    expect(fn () => app(SessionManager::class)->start('alice', 'org_x', ['pwd']))
        ->toThrow(ActionDenied::class, 'device is not enrolled')
        // The veto has to land BEFORE the row, or "denied" is only cosmetic.
        ->and(Session::query()->count())->toBe(0);
});

it('blocks every login path, not just the one it was written for', function (): void {
    // The hook sits on SessionManager::start(), which is what makes this true for
    // magic links, SSO and a host's own password form without any of them knowing.
    $this->fakeActionTransport()->willDeny('blocked by risk policy');
    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://risk.example.test');

    $token = app(MagicLink::class)->request('sam@acme.test');

    expect(fn () => app(MagicLink::class)->redeem($token))->toThrow(ActionDenied::class)
        ->and(Session::query()->count())->toBe(0);
});

it('lets a login through when the post-login endpoint is unreachable — and blocks it when the host asks for that', function (): void {
    Http::fake(['*' => Http::response('down', 500)]);
    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://risk.example.test');

    // Default: fail OPEN. A customer's endpoint going down must not lock their whole
    // tenant out of every application.
    $session = app(SessionManager::class)->start('alice', 'org_x', ['pwd']);
    expect($session->exists)->toBeTrue();

    // The tradeoff is the host's to make, and the stricter reading is one key away.
    config()->set('cbox-id.external_actions.fail_policy.post_login', 'closed');

    expect(fn () => app(SessionManager::class)->start('bob', 'org_x', ['pwd']))
        ->toThrow(ActionDenied::class);
});

it('adds no hook query and no hook call to a login when nothing is registered', function (): void {
    Http::fake();
    $sessions = app(SessionManager::class);

    // First login populates the empty active set for (environment, post_login).
    $sessions->start('alice', 'org_x', ['pwd']);

    $warm = hookPointQueries(fn () => $sessions->start('alice', 'org_x', ['pwd']));

    config()->set('cbox-id.external_actions.cache_ttl', 0);
    $cold = hookPointQueries(fn () => $sessions->start('alice', 'org_x', ['pwd']));

    // The hottest path in the product must not pay a query per login for a feature
    // almost no environment has turned on.
    expect($warm)->toBeLessThan($cold);
    Http::assertNothingSent();
});

/*
|--------------------------------------------------------------------------
| pre_registration / post_registration
|--------------------------------------------------------------------------
*/

it('consults the pre-registration hook with the account that does not exist yet', function (): void {
    $transport = $this->fakeActionTransport();
    $this->registerActionEndpoint(HookPoint::PreRegistration, 'https://allowlist.example.test');

    app(Subjects::class)->create('sam@acme.test', 'Sam', 'a-perfectly-long-passphrase');

    expect(sentPayload($transport))->toBe([
        'user_id' => null,
        'email' => 'sam@acme.test',
        'name' => 'Sam',
        'has_password' => true,
    ]);
});

it('creates no account when a pre-registration hook denies', function (): void {
    $this->fakeActionTransport()->willDeny('domain is not on the allowlist');
    $this->registerActionEndpoint(HookPoint::PreRegistration, 'https://allowlist.example.test');

    expect(fn () => app(Subjects::class)->create('sam@other.test'))
        ->toThrow(ActionDenied::class, 'domain is not on the allowlist')
        ->and(User::query()->count())->toBe(0);
});

it('refuses a signup it could not check', function (): void {
    // Fail CLOSED: a gate that admits everyone while it is down is not a gate.
    Http::fake(['*' => Http::response('down', 500)]);
    $this->registerActionEndpoint(HookPoint::PreRegistration, 'https://allowlist.example.test');

    expect(fn () => app(Subjects::class)->create('sam@acme.test'))->toThrow(ActionDenied::class)
        ->and(User::query()->count())->toBe(0);
});

it('hands the post-registration hook the new subject id, and takes no veto from it', function (): void {
    $audit = $this->fakeAudit();
    $transport = $this->fakeActionTransport()->willDeny('too late to matter');
    $this->registerActionEndpoint(HookPoint::PostRegistration, 'https://crm.example.test');

    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam');

    expect(sentPayload($transport))->toBe([
        'user_id' => $subject->id,
        'email' => 'sam@acme.test',
        'name' => 'Sam',
        'has_password' => false,
    ])
        // The row is committed; a deny here cannot unmake it, so it must not pretend to.
        ->and(app(Subjects::class)->find($subject->id))->not->toBeNull();

    // …but it is not swallowed either — a receiver denying a notification is a real
    // signal, and the operator needs to be able to see it.
    $audit->assertRecorded('external_action.denied', fn (AuditEvent $event): bool => $event->targetId === 'post_registration'
        && $event->context['vetoable'] === false
        && $event->context['subject'] === $subject->id);
});

it('never hands a call site a veto from a hook point that cannot veto', function (): void {
    // Enforced in the pipeline rather than at each call site: a `post_*` caller that
    // forgot to ignore the outcome would otherwise fail an operation that has already
    // committed, and a future call site is exactly the place that forgets.
    $this->fakeActionTransport()->willDeny('too late to matter');
    $this->registerActionEndpoint(HookPoint::PostRegistration, 'https://crm.example.test');
    $this->registerActionEndpoint(HookPoint::PreRegistration, 'https://allowlist.example.test');

    $outcome = app(ActionPipeline::class)->run(
        HookPoint::PostRegistration,
        ActionContext::for(RegistrationPayload::after('u1', 'sam@acme.test', 'Sam', false)),
    );

    // …while the vetoing point next to it still vetoes, so this is a property of the
    // hook point and not of the pipeline having stopped denying.
    $gate = app(ActionPipeline::class)->run(
        HookPoint::PreRegistration,
        ActionContext::for(RegistrationPayload::before('sam@acme.test', 'Sam', false)),
    );

    expect($outcome->allowed)->toBeTrue()
        ->and($gate->allowed)->toBeFalse();
});

/*
|--------------------------------------------------------------------------
| pre_password_change / post_password_change
|--------------------------------------------------------------------------
*/

it('consults the password-change hook without ever putting the password on the wire', function (): void {
    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam', 'the-original-passphrase');

    $transport = $this->fakeActionTransport();
    $this->registerActionEndpoint(HookPoint::PrePasswordChange, 'https://siem.example.test');

    app(Subjects::class)->setPassword($subject->id, 'a-replacement-passphrase-entirely');

    // Exactly the subject, and nothing else: no plaintext, no hash, no derivative.
    expect(sentPayload($transport))->toBe(['user_id' => $subject->id])
        ->and(json_encode($transport->sent[0]['context']->toArray()))
        ->not->toContain('a-replacement-passphrase-entirely');
});

it('leaves the old credential in place when a pre-password-change hook denies', function (): void {
    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam', 'the-original-passphrase');

    $this->fakeActionTransport()->willDeny('outside the change window');
    $this->registerActionEndpoint(HookPoint::PrePasswordChange, 'https://siem.example.test');

    expect(fn () => app(Subjects::class)->setPassword($subject->id, 'a-replacement-passphrase-entirely'))
        ->toThrow(ActionDenied::class, 'outside the change window')
        ->and(app(Subjects::class)->verifyPassword($subject->id, 'the-original-passphrase'))->toBeTrue();
});

it('refuses a password change it could not check', function (): void {
    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam', 'the-original-passphrase');

    Http::fake(['*' => Http::response('down', 500)]);
    $this->registerActionEndpoint(HookPoint::PrePasswordChange, 'https://siem.example.test');

    expect(fn () => app(Subjects::class)->setPassword($subject->id, 'a-replacement-passphrase-entirely'))
        ->toThrow(ActionDenied::class)
        ->and(app(Subjects::class)->verifyPassword($subject->id, 'the-original-passphrase'))->toBeTrue();
});

it('notifies after a password change and does not roll it back on a deny', function (): void {
    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam', 'the-original-passphrase');

    $transport = $this->fakeActionTransport()->willDeny('too late to matter');
    $this->registerActionEndpoint(HookPoint::PostPasswordChange, 'https://siem.example.test');

    app(Subjects::class)->setPassword($subject->id, 'a-replacement-passphrase-entirely');

    expect(sentPayload($transport))->toBe(['user_id' => $subject->id])
        ->and(app(Subjects::class)->verifyPassword($subject->id, 'a-replacement-passphrase-entirely'))->toBeTrue();
});

it('does not consult a password hook for an imported hash', function (): void {
    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam');

    $transport = $this->fakeActionTransport();
    $this->registerActionEndpoint(HookPoint::PrePasswordChange, 'https://siem.example.test');
    $this->registerActionEndpoint(HookPoint::PostPasswordChange, 'https://siem.example.test');

    // A bulk migration carries credentials that were set in the system being migrated
    // FROM. Firing per row would mean one blocking HTTP call per imported user.
    app(Subjects::class)->storeCredential($subject->id, password_hash('imported', PASSWORD_BCRYPT));

    $transport->assertNothingSent();
});

/*
|--------------------------------------------------------------------------
| the hook point that was NOT added
|--------------------------------------------------------------------------
*/

it('already covers a client-credentials exchange at token minting', function (): void {
    $transport = $this->fakeActionTransport();
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');

    $client = $this->makeClient(['api.read'])->client;
    app(TokenIssuer::class)->issueClientCredentials($client, ['api.read']);

    // A separate `credentials_exchange` point would be a second name for this call,
    // with a second endpoint to register and a second timeout to pay.
    expect(sentPayload($transport)['grant'])->toBe('client_credentials')
        ->and(sentPayload($transport)['user_id'])->toBeNull()
        ->and(HookPoint::tryFrom('credentials_exchange'))->toBeNull();
});

/*
|--------------------------------------------------------------------------
| fail policy resolution
|--------------------------------------------------------------------------
*/

it('defaults every gate closed and only the login hook open', function (): void {
    expect(HookPoint::TokenMinting->failPolicy())->toBe(FailPolicy::FailClosed)
        ->and(HookPoint::PreRegistration->failPolicy())->toBe(FailPolicy::FailClosed)
        ->and(HookPoint::PrePasswordChange->failPolicy())->toBe(FailPolicy::FailClosed)
        ->and(HookPoint::PostLogin->failPolicy())->toBe(FailPolicy::FailOpen)
        ->and(HookPoint::PostRegistration->failPolicy())->toBe(FailPolicy::FailOpen)
        ->and(HookPoint::PostPasswordChange->failPolicy())->toBe(FailPolicy::FailOpen);
});

it('resolves a fail policy per hook, then globally, then by the point\'s own default', function (): void {
    // Unset by default, so each point's own default applies.
    expect(FailPolicy::for(HookPoint::PostLogin))->toBe(FailPolicy::FailOpen)
        ->and(FailPolicy::for(HookPoint::TokenMinting))->toBe(FailPolicy::FailClosed);

    // The global switch still means what it always meant, in both directions.
    config()->set('cbox-id.external_actions.fail_open', true);
    expect(FailPolicy::for(HookPoint::TokenMinting))->toBe(FailPolicy::FailOpen);

    config()->set('cbox-id.external_actions.fail_open', false);
    expect(FailPolicy::for(HookPoint::PostLogin))->toBe(FailPolicy::FailClosed);

    // …and the per-hook key outranks it.
    config()->set('cbox-id.external_actions.fail_policy.post_login', 'open');
    expect(FailPolicy::for(HookPoint::PostLogin))->toBe(FailPolicy::FailOpen)
        ->and(FailPolicy::for(HookPoint::TokenMinting))->toBe(FailPolicy::FailClosed);

    // A typo must not quietly open a gate.
    config()->set('cbox-id.external_actions.fail_policy.post_login', 'opne');
    expect(FailPolicy::for(HookPoint::PostLogin))->toBe(FailPolicy::FailClosed);
});

it('keeps one tenant\'s registration and login hooks away from another', function (): void {
    $transport = $this->fakeActionTransport();

    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://acme.example.test', 'org_acme');
    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://globex.example.test', 'org_globex');
    $this->registerActionEndpoint(HookPoint::PostLogin, 'https://environment.example.test');

    app(SessionManager::class)->start('alice', 'org_acme', ['pwd']);

    // A login payload carries the user, their org and their IP; a hook that fires for
    // the wrong tenant is both an exfiltration channel and a way to deny their logins.
    expect($transport->sentTo('https://acme.example.test'))->toBeTrue()
        ->and($transport->sentTo('https://environment.example.test'))->toBeTrue();
    $transport->assertNotSentTo('https://globex.example.test');
})->group('isolation');
