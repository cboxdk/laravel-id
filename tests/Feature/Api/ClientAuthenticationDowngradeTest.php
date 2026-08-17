<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @group security
 *
 * A client that holds a credential must present it — both ways it could stop being asked.
 *
 * `ClientAuthenticator::authenticate()` decides this with a disjunction, and its docblock
 * records two real vulnerabilities that shaped it, one per arm. Neither arm had a test:
 * deleting either left the whole `tests/Feature/Api` suite green, which is how a fix for
 * an authentication bypass becomes a comment.
 *
 * ASSERTED AT `/oauth/revoke`, which is the endpoint that calls `authenticate()`. My first
 * version used the client-credentials grant and proved nothing: that path calls
 * `authenticateConfidential()`, a different method which demands a secret unconditionally,
 * so it answered 401 with the guard intact AND with either arm deleted. The mutation is
 * what exposed that — three deletions, including one that should have broken the positive
 * control, all left the tests green.
 *
 * Revocation is also where this matters most in practice: it is the one back-channel call
 * a public client is allowed to make on `client_id` alone, so it is exactly where a
 * confidential client must not be able to look like one.
 */
it('refuses a private_key_jwt client that presents no assertion and no secret', function (): void {
    // A confidential client whose credential is its KEY SET. The registry deliberately
    // issues no secret to one of these — one credential mechanism, not two — so
    // `secret_hash` is null by design rather than by omission, and a guard keyed on
    // "is a secret stored" skips verification entirely.
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'Assertion client',
        ClientType::Confidential,
        grantTypes: ['client_credentials'],
        scopes: ['api.read'],
        jwks: ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'n' => 'abc', 'e' => 'AQAB']]],
    ));

    expect($registered->secret)->toBeNull()
        ->and($registered->client->secret_hash)->toBeNull();

    $this->postJson('/oauth/revoke', [
        'token' => 'whatever',
        'client_id' => $registered->client->client_id,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
})->group('security');

/**
 * The same hole from the other side, and the reason the condition is a disjunction.
 *
 * RFC 7592 lets a client rewrite its own `token_endpoint_auth_method` to `none` through
 * `PUT /oauth/register/{client}`, which flips its type to Public WITHOUT clearing
 * `secret_hash`. Keying on type alone therefore let anyone holding a registration access
 * token downgrade a confidential client and then authenticate on `client_id` alone.
 */
it('refuses a client downgraded to public while its secret is still on file', function (): void {
    $registered = $this->makeClient();

    expect($registered->client->secret_hash)->not->toBeNull();

    // Exactly what an RFC 7592 update does: the type changes, the secret does not.
    Client::query()->whereKey($registered->client->id)->update(['type' => ClientType::Public->value]);

    $this->postJson('/oauth/revoke', [
        'token' => 'whatever',
        'client_id' => $registered->client->client_id,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
})->group('security');

/**
 * The positive control, and not a decorative one: a guard that refused every client would
 * satisfy both tests above while closing revocation to the public clients it was recently
 * opened for — the PKCE apps that most need to drop a refresh token on sign-out.
 */
it('still admits a genuine public client on its client_id alone', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'PKCE app',
        ClientType::Public,
        redirectUris: ['https://app.test/cb'],
        grantTypes: ['authorization_code'],
        scopes: ['openid'],
    ));

    expect($registered->client->secret_hash)->toBeNull();

    // RFC 7009: an unknown token is a 200. What is being asserted is that the CLIENT got
    // through the door, not what it found on the other side.
    $this->postJson('/oauth/revoke', [
        'token' => 'whatever',
        'client_id' => $registered->client->client_id,
    ])->assertOk();
})->group('security');

it('still admits a confidential client presenting its secret', function (): void {
    $registered = $this->makeClient();

    $this->postJson('/oauth/revoke', [
        'token' => 'whatever',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertOk();
})->group('security');
