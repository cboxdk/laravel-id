<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function decisionToken(string $userId = 'alice', string $org = 'org_x'): string
{
    $registered = test()->makeClient(['openid']);

    return app(TokenIssuer::class)->issueForUser($registered->client, $userId, $org, ['openid'])->token;
}

it('answers permission and entitlement checks live in a single call', function (): void {
    $token = decisionToken();

    app(RelationshipStore::class)->write(new Relationship('org_x', 'ticket', '42', 'manage', 'user', 'alice'));
    app(EntitlementWriter::class)->set('org_x', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);

    $this->postJson('/oauth/decisions', [
        'permissions' => [
            ['relation' => 'manage', 'resource' => 'ticket:42'],
            ['relation' => 'manage', 'resource' => 'ticket:99'],
        ],
        'entitlements' => ['plan', 'seats'],
    ], ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonPath('subject.id', 'alice')
        ->assertJsonPath('subject.type', 'user')
        ->assertJsonPath('organization', 'org_x')
        ->assertJsonPath('permissions.0.allowed', true)   // explicitly granted
        ->assertJsonPath('permissions.1.allowed', false)  // deny-by-default
        ->assertJsonPath('entitlements.plan.value.tier', 'pro')
        ->assertJsonPath('entitlements.seats', null);
});

it('reflects a plan change on the next decision — no new token, no disruption', function (): void {
    $token = decisionToken();
    $writer = app(EntitlementWriter::class);

    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);

    $call = fn () => $this->postJson('/oauth/decisions', ['entitlements' => ['plan']], ['Authorization' => 'Bearer '.$token]);

    expect($call()->json('entitlements.plan.value.tier'))->toBe('pro');

    // The customer downgrades in billing; the SAME token now sees 'free' at once.
    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'free']), EntitlementSource::Billing);

    expect($call()->json('entitlements.plan.value.tier'))->toBe('free');
});

it('rejects a missing or inactive token', function (): void {
    $this->postJson('/oauth/decisions', [])->assertStatus(401);
    $this->postJson('/oauth/decisions', [], ['Authorization' => 'Bearer not-a-real-token'])->assertStatus(401);
});

/**
 * A token minted for someone else's API must not work here.
 *
 * UserInfo has refused a wrong-audience token for some time, with a docblock explaining
 * that a token minted for a specific RFC 8707 resource must not be replayable to harvest
 * identity claims. This endpoint answers with strictly more — the subject's entire
 * permission and entitlement set in the organization — and had neither that check nor a
 * scope requirement.
 *
 * The scenario: an org registers app A with `resource=https://app-a.example`. Anyone
 * holding a token audienced to app A — the app itself, or whoever compromises it —
 * replays it here and enumerates that user's whole authorization surface. UserInfo says
 * no to the identical token.
 */
it('refuses an access token minted for a different resource', function (): void {
    $registered = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)
        ->issueForUser($registered->client, 'alice', 'org_x', ['openid'], 'https://app-a.example')
        ->token;

    $this->postJson('/oauth/decisions', ['entitlements' => ['plan']], ['Authorization' => 'Bearer '.$token])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate');
});

/**
 * The scope gate is opt-in, because this endpoint has always accepted any active token
 * and switching it on unannounced would refuse every integration at once. Both states are
 * pinned: a deployment that has not opted in is unaffected, and one that has gets a
 * refusal naming the scope to request rather than a bare 403.
 */
it('requires the decisions scope only where the operator asked for it', function (): void {
    $token = decisionToken();
    $call = fn () => $this->postJson('/oauth/decisions', ['entitlements' => ['plan']], ['Authorization' => 'Bearer '.$token]);

    config(['cbox-id.oauth.decisions.require_scope' => false]);
    $call()->assertOk();

    config(['cbox-id.oauth.decisions.require_scope' => true]);
    $call()->assertStatus(403)->assertJsonPath('error', 'insufficient_scope');
});

/**
 * RFC 6750 §3 makes `WWW-Authenticate` a MUST on a 401. Three distinct causes shared one
 * bare `{"error":"invalid_token"}` with no description, so a client had nothing to log and
 * nothing to act on — and TokenController had already solved this one file over, noting
 * that several real client libraries treat a bare 401 as fatal.
 */
it('says which of the three refusals happened', function (): void {
    $noToken = $this->postJson('/oauth/decisions', []);
    $badToken = $this->postJson('/oauth/decisions', [], ['Authorization' => 'Bearer not-a-real-token']);

    foreach ([$noToken, $badToken] as $response) {
        $response->assertStatus(401)->assertHeader('WWW-Authenticate');
        expect($response->json('error_description'))->toBeString()->not->toBe('');
    }

    expect($noToken->json('error_description'))->not->toBe($badToken->json('error_description'));
});
