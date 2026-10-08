<?php

declare(strict_types=1);

use Cbox\Id\Identity\Models\Session;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\Enums\AuthenticationShortfall;
use Cbox\Id\OAuthServer\Exceptions\InvalidAuthenticationRequirement;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

/*
 * RFC 9470 — OAuth 2.0 Step Up Authentication Challenge.
 *
 * The pieces both ends of step-up share: the resource server's challenge
 * (`insufficient_user_authentication` with `acr_values` / `max_age`), the requirement it
 * checks a token against, and the reading of the same two parameters off an
 * authorization request. One rule on both sides, or a token the authorization server
 * thought good enough is refused by the resource that asked for it, and the client loops.
 */

const STEP_UP_AAL1 = 'urn:cbox-id:aal1';
const STEP_UP_AAL2 = 'urn:cbox-id:aal2';
const STEP_UP_NOW = 1_800_000_000;

// --- The challenge header (RFC 9470 §3) ---------------------------------------------------

it('renders the RFC 9470 §3 acr_values challenge exactly as the RFC example shows it', function (): void {
    $challenge = (new BearerChallenge)->insufficientUserAuthentication(['myACR'], null, 'A different authentication level is required');

    expect($challenge->header())->toBe(
        'Bearer error="insufficient_user_authentication", error_description="A different authentication level is required", acr_values="myACR"',
    )->and($challenge->error)->toBe(BearerChallenge::INSUFFICIENT_USER_AUTHENTICATION);
});

it('renders max_age as a quoted-string, as the RFC 9470 §3 example does', function (): void {
    expect((new BearerChallenge)->insufficientUserAuthentication([], 5, 'More recent authentication is required')->header())
        ->toBe('Bearer error="insufficient_user_authentication", error_description="More recent authentication is required", max_age="5"');

    // Zero is a real requirement ("authenticate now"), not an absent one.
    expect((new BearerChallenge)->withMaxAge(0)->header())->toBe('Bearer max_age="0"');
});

it('orders parameters after scope and keeps resource_metadata, realm and scheme', function (): void {
    $resource = new ProtectedResource('https://h.example.test/mcp', ['mcp:write']);

    $header = BearerChallenge::for($resource)
        ->withScopes(['mcp:write'])
        ->withScheme('DPoP')
        ->insufficientUserAuthentication([STEP_UP_AAL2, STEP_UP_AAL1], 300, 'Step up')
        ->header();

    expect($header)->toBe(
        'DPoP resource_metadata="https://h.example.test/.well-known/oauth-protected-resource/mcp", '
        .'error="insufficient_user_authentication", error_description="Step up", scope="mcp:write", '
        .'acr_values="urn:cbox-id:aal2 urn:cbox-id:aal1", max_age="300"',
    );
});

it('carries acr_values and max_age through every other wither', function (): void {
    $challenge = (new BearerChallenge)->withAcrValues(['a'])->withMaxAge(10)
        ->withError('invalid_token')->withScopes(['s'])->withScheme('DPoP');

    expect($challenge->acrValues)->toBe(['a'])
        ->and($challenge->maxAge)->toBe(10)
        ->and($challenge->withMaxAge(null)->header())->toBe('DPoP error="invalid_token", scope="s", acr_values="a"');
});

it('escapes an error_description that tries to smuggle a parameter', function (): void {
    expect((new BearerChallenge)->insufficientUserAuthentication(['x'], null, "say \"hi\", max_age=\"0\"\r\nX: y")->header())
        ->toBe('Bearer error="insufficient_user_authentication", error_description="say \"hi\", max_age=\"0\"  X: y", acr_values="x"');
});

it('refuses a negative max_age and an acr value that would split in two', function (): void {
    expect(fn () => new BearerChallenge(maxAge: -1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => (new BearerChallenge)->withAcrValues(['two words']))->toThrow(InvalidArgumentException::class)
        ->and(fn () => (new BearerChallenge)->withAcrValues(['']))->toThrow(InvalidArgumentException::class);
});

it('leaves the header of every existing caller byte-for-byte unchanged', function (): void {
    // The 1.22 shapes: bare, resource-pointed, errored, scoped, DPoP, realm.
    $resource = new ProtectedResource('https://h.example.test/mcp', ['mcp:write']);

    expect((new BearerChallenge)->header())->toBe('Bearer')
        ->and(BearerChallenge::for($resource)->withError('invalid_token')->header())
        ->toBe('Bearer resource_metadata="https://h.example.test/.well-known/oauth-protected-resource/mcp", error="invalid_token"')
        ->and((new BearerChallenge('https://m', 'insufficient_scope', 'd', ['a', 'b'], 'api', 'DPoP'))->header())
        ->toBe('DPoP realm="api", resource_metadata="https://m", error="insufficient_scope", error_description="d", scope="a b"');
});

// --- The requirement (both sides) ---------------------------------------------------------

it('meets aal1 with either level and aal2 only with aal2', function (?string $acr, string $required, bool $met): void {
    $assessment = AuthenticationRequirement::of($required)->assess($acr, STEP_UP_NOW, STEP_UP_NOW);

    expect($assessment->isSatisfied())->toBe($met)
        ->and($assessment->requiresStepUp())->toBe(! $met)
        ->and($assessment->requiresReauthentication())->toBeFalse();
})->with([
    'aal1 meets aal1' => [STEP_UP_AAL1, STEP_UP_AAL1, true],
    'aal2 meets aal1' => [STEP_UP_AAL2, STEP_UP_AAL1, true],
    'aal2 meets aal2' => [STEP_UP_AAL2, STEP_UP_AAL2, true],
    'aal1 does not meet aal2' => [STEP_UP_AAL1, STEP_UP_AAL2, false],
    // Fail closed: a token that does not say what it achieved has not shown it.
    'no acr does not meet aal1' => [null, STEP_UP_AAL1, false],
    'a foreign acr does not meet aal1' => ['urn:example:loa3', STEP_UP_AAL1, false],
]);

it('reads the strongest class this server asserts, ignoring foreign values', function (): void {
    expect((new AuthenticationRequirement([STEP_UP_AAL1, STEP_UP_AAL2]))->requiredClass())->toBe(AuthenticationContextClass::Aal2)
        ->and((new AuthenticationRequirement(['urn:example:loa3', STEP_UP_AAL1]))->requiredClass())->toBe(AuthenticationContextClass::Aal1)
        ->and((new AuthenticationRequirement(['urn:example:loa3']))->requiredClass())->toBeNull()
        ->and((new AuthenticationRequirement(['urn:example:loa3']))->isEmpty())->toBeTrue()
        ->and((new AuthenticationRequirement(['urn:example:loa3']))->assess(null, null)->isSatisfied())->toBeTrue();
});

it('holds max_age to the leeway boundary, inclusive', function (int $age, bool $met): void {
    $requirement = AuthenticationRequirement::of(maxAge: 300);
    $assessment = $requirement->assess(STEP_UP_AAL1, STEP_UP_NOW - $age, STEP_UP_NOW);

    expect($assessment->isSatisfied())->toBe($met)
        ->and($assessment->requiresReauthentication())->toBe(! $met);
})->with([
    'just now' => [0, true],
    'at max_age' => [300, true],
    'at max_age + leeway' => [300 + AuthenticationRequirement::DEFAULT_MAX_AGE_LEEWAY_SECONDS, true],
    'one second past the leeway' => [301 + AuthenticationRequirement::DEFAULT_MAX_AGE_LEEWAY_SECONDS, false],
    'yesterday' => [86_400, false],
]);

it('lets max_age=0 be met by a login that has only just happened', function (): void {
    // The case the parameter exists for. Without leeway it could never succeed: every
    // session was created strictly before the instant it is checked.
    $requirement = AuthenticationRequirement::of(maxAge: 0);

    expect($requirement->assess(null, STEP_UP_NOW - 2, STEP_UP_NOW)->isSatisfied())->toBeTrue()
        ->and($requirement->assess(null, STEP_UP_NOW - 2, STEP_UP_NOW, leeway: 0)->isSatisfied())->toBeFalse();
});

it('treats a login with no auth_time as too old when max_age is asked for', function (): void {
    $assessment = AuthenticationRequirement::of(STEP_UP_AAL2, 300)->assess(STEP_UP_AAL2, null, STEP_UP_NOW);

    expect($assessment->shortfalls)->toBe([AuthenticationShortfall::TooOld])
        ->and($assessment->authorizationError())->toBe('login_required');

    // And no max_age, no question about the time.
    expect(AuthenticationRequirement::of(STEP_UP_AAL2)->assess(STEP_UP_AAL2, null, STEP_UP_NOW)->isSatisfied())->toBeTrue();
});

it('reports both shortfalls, the age first, and the right error for each side', function (): void {
    $requirement = AuthenticationRequirement::of(AuthenticationContextClass::Aal2, 60);
    $assessment = $requirement->assess(STEP_UP_AAL1, STEP_UP_NOW - 3600, STEP_UP_NOW);

    expect($assessment->shortfalls)->toBe([AuthenticationShortfall::TooOld, AuthenticationShortfall::ContextNotMet])
        ->and($assessment->authorizationError())->toBe('login_required')
        ->and($assessment->errorDescription())->toContain('max_age');

    $weak = $requirement->assess(STEP_UP_AAL1, STEP_UP_NOW, STEP_UP_NOW);

    expect($weak->authorizationError())->toBe('unmet_authentication_requirements')
        ->and($weak->errorDescription())->toContain(STEP_UP_AAL2);

    expect($requirement->assess(STEP_UP_AAL2, STEP_UP_NOW, STEP_UP_NOW)->authorizationError())->toBeNull();
});

it('builds the resource server challenge from the whole requirement', function (): void {
    $resource = new ProtectedResource('https://h.example.test/mcp', ['mcp:write']);
    $requirement = AuthenticationRequirement::of(AuthenticationContextClass::Aal2, 600);

    // Only the class fell short, but the challenge still names max_age: the client turns
    // it into its next authorization request, and must come back meeting both.
    $challenge = $requirement->assess(STEP_UP_AAL1, STEP_UP_NOW, STEP_UP_NOW)->challenge(BearerChallenge::for($resource));

    expect($challenge?->header())->toBe(
        'Bearer resource_metadata="https://h.example.test/.well-known/oauth-protected-resource/mcp", '
        .'error="insufficient_user_authentication", '
        .'error_description="The requested authentication context (urn:cbox-id:aal2) was not met.", '
        .'acr_values="urn:cbox-id:aal2", max_age="600"',
    );

    expect($requirement->assess(STEP_UP_AAL2, STEP_UP_NOW, STEP_UP_NOW)->challenge())->toBeNull();
});

it('assesses a validated token by its acr and auth_time claims', function (): void {
    $token = Introspection::active('user_1', 'cid', ['openid'], ['acr' => STEP_UP_AAL2, 'auth_time' => STEP_UP_NOW - 30]);
    $machine = Introspection::active('cid', 'cid', ['api.read'], []);

    expect($token->acr())->toBe(STEP_UP_AAL2)
        ->and($token->authTime())->toBe(STEP_UP_NOW - 30)
        ->and(AuthenticationRequirement::of(STEP_UP_AAL2, 60)->assessToken($token, STEP_UP_NOW)->isSatisfied())->toBeTrue()
        ->and(AuthenticationRequirement::of(STEP_UP_AAL1)->assessToken($machine, STEP_UP_NOW)->requiresStepUp())->toBeTrue()
        ->and(AuthenticationRequirement::none()->assessToken($machine, STEP_UP_NOW)->isSatisfied())->toBeTrue();
});

it('assesses a session by its amr and its authentication time', function (): void {
    $this->travelTo(Carbon::createFromTimestamp(STEP_UP_NOW));

    $password = new Session;
    $password->amr = ['pwd'];
    $password->created_at = Carbon::createFromTimestamp(STEP_UP_NOW - 120);

    $mfa = new Session;
    $mfa->amr = ['pwd', 'mfa'];
    $mfa->created_at = Carbon::createFromTimestamp(STEP_UP_NOW - 120);

    $aal2 = AuthenticationRequirement::of(AuthenticationContextClass::Aal2);

    expect($aal2->assessSession($password)->requiresStepUp())->toBeTrue()
        ->and($aal2->assessSession($password)->authorizationError())->toBe('unmet_authentication_requirements')
        ->and($aal2->assessSession($mfa)->isSatisfied())->toBeTrue()
        ->and($aal2->assessSession($mfa)->acr)->toBe(STEP_UP_AAL2)
        // Freshness from created_at, against the application clock.
        ->and(AuthenticationRequirement::of(maxAge: 30)->assessSession($mfa)->requiresReauthentication())->toBeTrue()
        ->and(AuthenticationRequirement::of(maxAge: 120)->assessSession($mfa)->isSatisfied())->toBeTrue()
        // No session meets nothing but the empty requirement.
        ->and($aal2->assessSession(null)->isSatisfied())->toBeFalse()
        ->and(AuthenticationRequirement::none()->assessSession(null)->isSatisfied())->toBeTrue();
});

// --- Reading the authorization request (OIDC Core §3.1.2.1) -----------------------------

it('reads acr_values and max_age off a query request and a pushed payload alike', function (): void {
    $fromQuery = AuthenticationRequirement::fromAuthorizationRequest(
        Request::create('/oauth/authorize', 'GET', ['acr_values' => '  urn:cbox-id:aal2   urn:cbox-id:aal1 urn:cbox-id:aal2 ', 'max_age' => '300']),
    );
    $fromPar = AuthenticationRequirement::fromAuthorizationRequest(['acr_values' => STEP_UP_AAL2, 'max_age' => 0]);

    expect($fromQuery->acrValues)->toBe([STEP_UP_AAL2, STEP_UP_AAL1])
        ->and($fromQuery->maxAge)->toBe(300)
        ->and($fromPar->acrValues)->toBe([STEP_UP_AAL2])
        ->and($fromPar->maxAge)->toBe(0)
        ->and(AuthenticationRequirement::fromAuthorizationRequest([])->isEmpty())->toBeTrue()
        ->and(AuthenticationRequirement::fromAuthorizationRequest(['max_age' => '', 'acr_values' => ''])->isEmpty())->toBeTrue()
        ->and(AuthenticationRequirement::fromAuthorizationRequest(['max_age' => '007'])->maxAge)->toBe(7);
});

it('refuses a malformed max_age as invalid_request', function (mixed $maxAge): void {
    try {
        AuthenticationRequirement::fromAuthorizationRequest(['max_age' => $maxAge]);
        $this->fail('a malformed max_age was accepted');
    } catch (InvalidAuthenticationRequirement $e) {
        expect($e->error)->toBe('invalid_request');
    }
})->with([
    'negative' => ['-1'],
    'negative int' => [-5],
    'fraction' => ['1.5'],
    'exponent' => ['1e3'],
    'signed' => ['+5'],
    'words' => ['soon'],
    'padded' => [' 5'],
    'overflowing' => ['99999999999999999999'],
    'array' => [['5']],
]);

it('refuses an acr_values that is not a string', function (): void {
    expect(fn () => AuthenticationRequirement::fromAuthorizationRequest(['acr_values' => [STEP_UP_AAL2]]))
        ->toThrow(InvalidAuthenticationRequirement::class);
});

// --- What goes on the access token (RFC 9470 §6.1) ----------------------------------------

it('derives acr from amr and never invents one', function (): void {
    expect((new AuthenticationEvent(STEP_UP_NOW, ['pwd', 'mfa']))->claims())->toBe(['auth_time' => STEP_UP_NOW, 'acr' => STEP_UP_AAL2])
        ->and((new AuthenticationEvent(STEP_UP_NOW, ['pwd']))->claims())->toBe(['auth_time' => STEP_UP_NOW, 'acr' => STEP_UP_AAL1])
        // A CIBA approval: a time, but no record of HOW — so no class is asserted.
        ->and((new AuthenticationEvent(STEP_UP_NOW))->claims())->toBe(['auth_time' => STEP_UP_NOW])
        ->and((new AuthenticationEvent)->isEmpty())->toBeTrue()
        ->and((new AuthenticationEvent)->claims())->toBe([]);
});
