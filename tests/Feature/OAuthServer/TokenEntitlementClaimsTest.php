<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @return array<string, mixed>
 */
function tokenPayload(string $jwt): array
{
    return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
}

it('embeds Claims-mode entitlements in the token but leaves DecisionApi ones live', function (): void {
    $writer = app(EntitlementWriter::class);
    // Coarse, slow-changing → Claims (embedded); instant-critical → DecisionApi (live only).
    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'pro'], EnforcementMode::Claims), EntitlementSource::Billing);
    $writer->set('org_x', new EntitlementInput('seats', ['limit' => 50], EnforcementMode::DecisionApi), EntitlementSource::Billing);

    $registered = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', 'org_x', ['openid'])->token;

    $payload = tokenPayload($token);

    expect($payload['ent'])->toBe(['plan' => ['tier' => 'pro']])   // only the Claims-mode key
        ->and($payload['ent'])->not->toHaveKey('seats')            // DecisionApi stays live
        ->and($payload['ent_ver'])->toBeGreaterThan(0);
});

it('omits the ent claim entirely when embedding is disabled', function (): void {
    config(['cbox-id.oauth.embed_entitlements' => false]);
    app(EntitlementWriter::class)->set('org_x', new EntitlementInput('plan', ['tier' => 'pro'], EnforcementMode::Claims), EntitlementSource::Billing);

    $registered = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', 'org_x', ['openid'])->token;

    expect(tokenPayload($token))->not->toHaveKey('ent');
});

it('has no ent claim when the org has only DecisionApi entitlements', function (): void {
    app(EntitlementWriter::class)->set('org_x', new EntitlementInput('seats', ['limit' => 5], EnforcementMode::DecisionApi), EntitlementSource::Billing);

    $registered = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', 'org_x', ['openid'])->token;

    expect(tokenPayload($token))->not->toHaveKey('ent');

    // The token still verifies and introspects normally.
    expect(app(TokenIntrospector::class)->introspect($token)->active)->toBeTrue();
});
