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
