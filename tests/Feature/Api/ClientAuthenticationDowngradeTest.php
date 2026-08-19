<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
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

/**
 * An RFC 7592 update retires the secret when the client says it no longer uses one.
 *
 * The downgrade bypass above is closed at the DOOR — `ClientAuthenticator` treats "secret
 * still on file" as proof the client is confidential, so a downgraded client cannot log in
 * on `client_id` alone. This is the other half, and it was left open: the row went on
 * carrying a live credential that the client's own registered metadata says is not in use.
 *
 * Reported by a third-party security pass and confirmed against the code before acting:
 * after updating a `client_secret_basic` client to `none`, its type flipped to Public and
 * `secret_hash` stayed exactly where it was.
 */
it('clears the secret when a client updates itself to an auth method that has none', function (string $method, array $extra): void {
    $registered = $this->makeClient();

    expect($registered->client->secret_hash)->not->toBeNull();

    $registrar = app(DynamicClientRegistration::class);

    $registrar->update($registered->client, $registrar->validate(array_merge([
        'client_name' => 'Updated',
        'token_endpoint_auth_method' => $method,
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
    ], $extra)));

    expect($registered->client->fresh()?->secret_hash)->toBeNull();
})->with([
    'downgraded to none' => ['none', []],
    'switched to private_key_jwt' => ['private_key_jwt', ['jwks' => ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'n' => 'abc', 'e' => 'AQAB']]]]],
])->group('security');

it('keeps the secret when the client still authenticates with one', function (): void {
    $registered = $this->makeClient();
    $before = $registered->client->secret_hash;

    $registrar = app(DynamicClientRegistration::class);

    $registrar->update($registered->client, $registrar->validate([
        'client_name' => 'Renamed but still confidential',
        'token_endpoint_auth_method' => 'client_secret_basic',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
    ]));

    // The positive control: clearing it unconditionally would lock every confidential
    // client out of its own account on the next metadata edit.
    expect($registered->client->fresh()?->secret_hash)->toBe($before);
})->group('security');

/**
 * @group security
 *
 * The return journey, which the downgrade fix above created and left unfinished.
 *
 * Clearing `secret_hash` when a client moves to `private_key_jwt` is right. But RFC 7592
 * lets it move back, and the update wrote `usesASharedSecret() ? $client->secret_hash :
 * null` — for a client whose hash had already been cleared, that is `null`. It arrived at
 * `client_secret_basic` with no password: every token request 401s, and the registration
 * response said nothing about why. The docblock on that line had described minting a fresh
 * one since the day it was written; only the comment did it.
 *
 * Asserted end to end, because "a secret came back in the response" and "that secret
 * authenticates" are separate claims and the second is the one that matters.
 */
it('mints a usable secret when a client updates back into a shared-secret method', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);

    $created = $this->postJson('/oauth/register', [
        'client_name' => 'Assertion first',
        'token_endpoint_auth_method' => 'private_key_jwt',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
        'jwks' => ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'n' => 'abc', 'e' => 'AQAB']]],
    ])->assertStatus(201);

    $clientId = $created->json('client_id');
    $auth = ['Authorization' => 'Bearer '.$created->json('registration_access_token')];

    // A key-set client holds no secret. That is the state the update has to resolve.
    expect($created->json('client_secret'))->toBeNull()
        ->and(Client::query()->where('client_id', $clientId)->value('secret_hash'))->toBeNull();

    $updated = $this->putJson('/oauth/register/'.$clientId, [
        'client_name' => 'Back to a password',
        'token_endpoint_auth_method' => 'client_secret_basic',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
    ], $auth)->assertOk();

    $secret = $updated->json('client_secret');

    expect($secret)->toBeString()->not->toBeEmpty();

    // It is a real credential, not a value in a response body: the endpoint that verifies
    // client secrets accepts this one and refuses a wrong one.
    $this->withHeaders(['Authorization' => 'Basic '.base64_encode($clientId.':'.$secret)])
        ->postJson('/oauth/revoke', ['token' => 'whatever'])
        ->assertOk();

    $this->withHeaders(['Authorization' => 'Basic '.base64_encode($clientId.':wrong')])
        ->postJson('/oauth/revoke', ['token' => 'whatever'])
        ->assertStatus(401);
})->group('security');
