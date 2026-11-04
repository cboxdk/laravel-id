<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthenticationAssessment;
use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Enums\AuthenticationIssuance;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Exceptions\AuthenticationStepUpRequired;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\Testing\FakeAuthenticationAssessment;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('assesses every session primitive before saving a session', function (array $amr): void {
    $fake = new FakeAuthenticationAssessment([new AuthenticationStepUpRequired('assessment-1'), null]);
    app()->instance(AuthenticationAssessment::class, $fake);
    $before = Session::query()->count();
    $events = Event::query()->where('type', 'user.session_started')->count();
    expect(fn () => app(SessionManager::class)->start('user-1', 'org-1', $amr, '203.0.113.1', 'agent'))
        ->toThrow(AuthenticationStepUpRequired::class);
    expect(Session::query()->count())->toBe($before)
        ->and($fake->calls[0]->subjectId)->toBe('user-1')
        ->and($fake->calls[0]->organizationId)->toBe('org-1')
        ->and($fake->calls[0]->amr)->toBe($amr)
        ->and($fake->calls[0]->issuance)->toBe(AuthenticationIssuance::Session)
        ->and($fake->calls[0]->ip)->toBe('203.0.113.1');
    expect(Event::query()->where('type', 'user.session_started')->count())->toBe($events);
    $session = app(SessionManager::class)->start('user-1', 'org-1', ['pwd', 'mfa']);
    $event = Event::query()->where('type', 'user.session_started')->latest('occurred_at')->firstOrFail();
    expect(Session::query()->count())->toBe($before + 1)
        ->and($event->payload['session_id'])->toBe($session->id)
        ->and($event->payload['amr'])->toBe(['pwd', 'mfa']);
})->with([[['pwd']], [['magic_link']], [['saml']], [['ciba']]]);

it('gates authenticated and legacy user tokens but not machine credentials', function (): void {
    $user = $this->makeUser();
    $client = $this->makeClient(['openid'])->client;
    $fake = new FakeAuthenticationAssessment([
        new AuthenticationStepUpRequired('assessment-1'),
        new AuthenticationStepUpRequired('assessment-2'),
        null,
    ]);
    app()->instance(AuthenticationAssessment::class, $fake);
    $issuer = app(TokenIssuer::class);
    expect(fn () => $issuer->issueForAuthenticatedUser($client, $user->id, null, ['openid'], new AuthenticationEvent(100, ['pwd'])))
        ->toThrow(InvalidGrant::class);
    expect(fn () => $issuer->issueForUser($client, $user->id, null, ['openid']))->toThrow(InvalidGrant::class);
    expect($fake->calls[0]->authenticatedAt)->toBe(100)
        ->and($fake->calls[0]->issuance)->toBe(AuthenticationIssuance::Token)
        ->and($fake->calls[1]->authenticatedAt)->toBeNull()
        ->and($fake->calls[1]->amr)->toBe([]);
    expect($issuer->issueForAuthenticatedUser($client, $user->id, null, ['openid'], new AuthenticationEvent(time(), ['pwd', 'mfa']))->token)->not->toBeEmpty();
    expect($issuer->issueClientCredentials($client, ['openid'])->token)->not->toBeEmpty();
    expect($fake->calls)->toHaveCount(3);
});

it('does not let an allowing assessment override the existing MFA mandate', function (): void {
    $user = $this->makeUser();
    $client = $this->makeClient(['openid'])->client;
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));
    app()->instance(AuthenticationAssessment::class, new FakeAuthenticationAssessment([null]));
    expect(fn () => app(TokenIssuer::class)->issueForAuthenticatedUser($client, $user->id, null, ['openid'], new AuthenticationEvent(time(), ['pwd'])))
        ->toThrow(InvalidGrant::class);
});
