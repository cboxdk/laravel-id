<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SignInMethods;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Exceptions\SignInMethodDisabled;
use Cbox\Id\Identity\Models\AuthPolicyRecord;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * THE ENVIRONMENT'S SIGN-IN METHODS, UNDER THE DEPLOYMENT'S CEILING.
 *
 * Passkeys, magic links and session lengths were the deployment's alone, so the person
 * administering one environment could not switch a method off or shorten a session for
 * their own people. They are on the environment's authentication policy now — and the
 * deployment is still the ceiling: an environment may switch off what the deployment
 * offers and shorten what it allows, never the reverse.
 */
beforeEach(function (): void {
    config()->set('cbox-id.sign_in.passkeys', true);
    config()->set('cbox-id.sign_in.magic_link', true);
    config()->set('cbox-id.sessions.ttl_minutes', 480);
    config()->set('cbox-id.sessions.idle_minutes', 30);
});

it('offers everything the deployment offers until an environment says otherwise', function (): void {
    $methods = app(SignInMethods::class);

    expect($methods->passkeysEnabled())->toBeTrue()
        ->and($methods->magicLinkEnabled())->toBeTrue()
        ->and($methods->sessionAbsoluteMinutes())->toBe(480)
        ->and($methods->sessionIdleMinutes())->toBe(30);
});

it('lets an environment switch passkeys and magic links off', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(passkeys: false, magicLink: false));

    expect(app(SignInMethods::class)->passkeysEnabled())->toBeFalse()
        ->and(app(SignInMethods::class)->magicLinkEnabled())->toBeFalse();
});

it('lets the deployment switch a method off whatever the environment says', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(passkeys: true, magicLink: true));
    config()->set('cbox-id.sign_in.passkeys', 'false');
    config()->set('cbox-id.sign_in.magic_link', false);

    $methods = app(SignInMethods::class);

    expect($methods->passkeysEnabled())->toBeFalse()
        ->and($methods->deploymentAllowsPasskeys())->toBeFalse()
        ->and($methods->magicLinkEnabled())->toBeFalse();
});

it('bounds an environment\'s session lengths by the deployment\'s', function (): void {
    $policies = app(AuthPolicies::class);

    $policies->setForEnvironment(new AuthPolicy(sessionIdleMinutes: 10, sessionAbsoluteMinutes: 60));
    expect(app(SignInMethods::class)->sessionIdleMinutes())->toBe(10)
        ->and(app(SignInMethods::class)->sessionAbsoluteMinutes())->toBe(60);

    // Longer than the deployment allows: the deployment's maximum, not the environment's wish.
    $policies->setForEnvironment(new AuthPolicy(sessionIdleMinutes: 600, sessionAbsoluteMinutes: 10_000));
    expect(app(SignInMethods::class)->sessionIdleMinutes())->toBe(30)
        ->and(app(SignInMethods::class)->sessionAbsoluteMinutes())->toBe(480);
});

it('bounds an idle timeout by the absolute lifetime where the deployment sets no idle timeout', function (): void {
    config()->set('cbox-id.sessions.idle_minutes', 0);
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(sessionIdleMinutes: 900, sessionAbsoluteMinutes: 120));

    expect(app(SignInMethods::class)->sessionIdleMinutes())->toBe(120)
        ->and(app(SignInMethods::class)->deploymentSessionIdleMinutes())->toBe(0);
});

it('keeps the environment\'s settings when an organization override is layered on', function (): void {
    $policies = app(AuthPolicies::class);
    $policies->setForEnvironment(new AuthPolicy(passkeys: false, sessionAbsoluteMinutes: 60, botChallenge: false));
    // An override row holds these columns too — at their defaults — and must not revive them.
    $policies->setForOrganization('org_1', new AuthPolicy(mfa: MfaRequirement::Required));

    $effective = $policies->resolve('org_1');

    expect($effective->passkeys)->toBeFalse()
        ->and($effective->sessionAbsoluteMinutes)->toBe(60)
        ->and($effective->botChallenge)->toBeFalse()
        ->and($effective->mfa)->toBe(MfaRequirement::Required)
        ->and(AuthPolicy::isEnvironmentWide('passkeys'))->toBeTrue()
        ->and(AuthPolicy::isEnvironmentWide('minLength'))->toBeFalse();
});

it('stores and reads back every environment-wide field', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(
        passkeys: false,
        magicLink: false,
        sessionIdleMinutes: 15,
        sessionAbsoluteMinutes: 240,
        botChallenge: false,
    ));

    $read = AuthPolicyRecord::query()->whereNull('organization_id')->firstOrFail()->toPolicy();

    expect($read->passkeys)->toBeFalse()
        ->and($read->magicLink)->toBeFalse()
        ->and($read->sessionIdleMinutes)->toBe(15)
        ->and($read->sessionAbsoluteMinutes)->toBe(240)
        ->and($read->botChallenge)->toBeFalse();
});

it('answers per environment', function (): void {
    $environments = app(EnvironmentContext::class);
    $policies = app(AuthPolicies::class);

    $environments->runAs(GenericEnvironment::of('env_strict'), fn () => $policies->setForEnvironment(new AuthPolicy(magicLink: false)));

    $here = $environments->runAs(GenericEnvironment::of('env_strict'), fn (): bool => app(SignInMethods::class)->magicLinkEnabled());
    $there = $environments->runAs(GenericEnvironment::of('env_open'), fn (): bool => app(SignInMethods::class)->magicLinkEnabled());

    expect($here)->toBeFalse()->and($there)->toBeTrue();
});

// ── Enforced at the primitives, not only at a host's routes ─────────────────────────

it('refuses to mint or redeem a magic link where they are off', function (): void {
    $token = app(MagicLink::class)->request('ada@example.test');

    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(magicLink: false));

    // A link minted while the method was on is closed with it.
    expect(fn () => app(MagicLink::class)->redeem($token))->toThrow(SignInMethodDisabled::class)
        ->and(fn () => app(MagicLink::class)->request('ada@example.test'))->toThrow(SignInMethodDisabled::class);
});

it('refuses passkey sign-in and enrolment where passkeys are off, before looking anything up', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(passkeys: false));

    try {
        app(Passkeys::class)->authenticate('no-such-credential', 'challenge', '{}');
        $this->fail('expected a refusal');
    } catch (SignInMethodDisabled $refused) {
        // Not UnknownCredential: a closed door answers the same for every credential id.
        expect($refused->method)->toBe('passkeys');
    }

    expect(fn () => app(Passkeys::class)->register('user-1', 'challenge', '{}'))->toThrow(SignInMethodDisabled::class);
});

// ── Session lengths, applied ────────────────────────────────────────────────────────

it('starts a session with the environment\'s shorter absolute lifetime', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(sessionAbsoluteMinutes: 60));
    $user = app(Subjects::class)->create('ada@example.test');

    $this->freezeSecond();
    $session = app(SessionManager::class)->start($user->id, null, ['pwd']);

    expect($session->refresh()->expires_at->equalTo(now()->addMinutes(60)))->toBeTrue();
});

it('ends a session after the environment\'s idle timeout', function (): void {
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(sessionIdleMinutes: 5));
    $user = app(Subjects::class)->create('ada@example.test');
    $session = app(SessionManager::class)->start($user->id, null, ['pwd']);

    $this->travel(4)->minutes();
    expect(app(SessionManager::class)->active($session->id))->not->toBeNull();

    $this->travel(6)->minutes();
    expect(app(SessionManager::class)->active($session->id))->toBeNull();
});

it('ends sessions already running when the environment shortens their lifetime', function (): void {
    $user = app(Subjects::class)->create('ada@example.test');
    $session = app(SessionManager::class)->start($user->id, null, ['pwd']);

    // Started under the deployment's eight hours; kept active so idleness is not the reason.
    foreach (range(1, 4) as $step) {
        $this->travel(20)->minutes();
        app(SessionManager::class)->active($session->id);
    }

    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(sessionAbsoluteMinutes: 60));

    expect(Session::query()->find($session->id)?->expires_at->isFuture())->toBeTrue()
        ->and(app(SessionManager::class)->active($session->id))->toBeNull();
});
