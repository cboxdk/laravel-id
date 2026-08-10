<?php

declare(strict_types=1);

use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Support\AttributeMapping;
use Cbox\Id\Provisioning\ValueObjects\ScimResult;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

it('POSTs a real scim+json User body with a bearer token', function (): void {
    Http::fake(['*' => Http::response(json_encode(['id' => 'remote-1', 'externalId' => 'user-1']), 201)]);
    $connection = $this->registerProvisioningConnection(secret: 'the-bearer-token')->connection;

    $resource = ScimSchema::userResource('user-1', ['userName' => 'u@example.com', 'active' => true]);
    $result = app(ScimClient::class)->createUser($connection, $resource);

    expect($result->status)->toBe(201)
        ->and($result->remoteId())->toBe('remote-1');

    Http::assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);

        return $request->method() === 'POST'
            && $request->url() === 'https://scim.downstream.test/scim/v2/Users'
            && $request->header('Authorization')[0] === 'Bearer the-bearer-token'
            && str_contains($request->header('Content-Type')[0], 'application/scim+json')
            && $body['schemas'] === [ScimSchema::USER_URN]
            && $body['externalId'] === 'user-1';
    });
});

it('PATCHes a PatchOp body to the remote id and GETs a filter for reconcile', function (): void {
    // A correctly-filtered SCIM ListResponse: exactly the record carrying our externalId.
    Http::fake(['*' => Http::response(json_encode(['schemas' => [ScimSchema::LIST_RESPONSE_URN], 'totalResults' => 1, 'Resources' => [['id' => 'remote-9', 'externalId' => 'user-1']]]), 200)]);
    $connection = $this->registerProvisioningConnection()->connection;

    app(ScimClient::class)->patchUser($connection, 'remote-9', [ScimSchema::setActive(false)]);
    $found = app(ScimClient::class)->findByExternalId($connection, 'user-1');

    expect($found)->toBe('remote-9');

    Http::assertSent(function (Request $request): bool {
        if ($request->method() !== 'PATCH') {
            return false;
        }
        $body = json_decode($request->body(), true);

        return $request->url() === 'https://scim.downstream.test/scim/v2/Users/remote-9'
            && $body['schemas'] === [ScimSchema::PATCH_OP_URN]
            && $body['Operations'][0] === ['op' => 'replace', 'path' => 'active', 'value' => false];
    });

    Http::assertSent(fn (Request $request): bool => $request->method() === 'GET'
        && str_contains(urldecode($request->url()), 'filter=externalId eq "user-1"'));
});

it('refuses a reconcile match from a server that ignores the filter and returns its whole list', function (): void {
    // A lenient/misconfigured SCIM peer ignores the unknown filter and returns every
    // user with 200. We must NOT adopt an arbitrary record as this subject's mirror.
    Http::fake(['*' => Http::response(json_encode([
        'schemas' => [ScimSchema::LIST_RESPONSE_URN],
        'totalResults' => 3,
        'Resources' => [
            ['id' => 'someone-else-1', 'externalId' => 'user-999'],
            ['id' => 'someone-else-2', 'externalId' => 'user-888'],
            ['id' => 'someone-else-3', 'externalId' => 'user-777'],
        ],
    ]), 200)]);
    $connection = $this->registerProvisioningConnection()->connection;

    expect(app(ScimClient::class)->findByExternalId($connection, 'user-1'))->toBeNull();
});

it('refuses a single reconcile result whose externalId does not actually match', function (): void {
    // Even a single-result response must carry the requested externalId — otherwise
    // the server matched on something else (or fabricated a row).
    Http::fake(['*' => Http::response(json_encode([
        'schemas' => [ScimSchema::LIST_RESPONSE_URN],
        'totalResults' => 1,
        'Resources' => [['id' => 'wrong-user', 'externalId' => 'user-2']],
    ]), 200)]);
    $connection = $this->registerProvisioningConnection()->connection;

    expect(app(ScimClient::class)->findByExternalId($connection, 'user-1'))->toBeNull();
});

it('exchanges an OAuth2 client-credentials grant for the bearer it presents', function (): void {
    Http::fake([
        'https://idp.downstream.test/token' => Http::response(json_encode(['access_token' => 'minted-access-token', 'token_type' => 'Bearer']), 200),
        'https://scim.downstream.test/*' => Http::response(json_encode(['id' => 'remote-2']), 201),
    ]);

    $connection = $this->registerProvisioningConnection(
        authScheme: AuthScheme::OAuth2ClientCredentials,
        secret: 'oauth-client-secret',
        authConfig: [
            'token_url' => 'https://idp.downstream.test/token',
            'client_id' => 'client-abc',
            'scope' => 'scim',
        ],
    )->connection;

    app(ScimClient::class)->createUser($connection, ScimSchema::userResource('user-2', ['userName' => 'x@example.com']));

    // The token endpoint got a standard client-credentials form grant.
    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://idp.downstream.test/token'
        && $request['grant_type'] === 'client_credentials'
        && $request['client_id'] === 'client-abc'
        && $request['client_secret'] === 'oauth-client-secret');

    // The SCIM call presented the minted access token, not the client secret.
    Http::assertSent(fn (Request $request): bool => str_starts_with($request->url(), 'https://scim.downstream.test/')
        && $request->header('Authorization')[0] === 'Bearer minted-access-token');
});

it('refreshes an expired OAuth access token instead of reusing a stale one', function (): void {
    // The client is a container singleton living across many jobs in a worker; a
    // cache with no expiry would serve a dead token forever and 401 every op.
    Http::fake([
        'https://idp.downstream.test/token' => Http::sequence()
            ->push(json_encode(['access_token' => 'token-1', 'expires_in' => 100]), 200)
            ->push(json_encode(['access_token' => 'token-2', 'expires_in' => 100]), 200),
        'https://scim.downstream.test/*' => Http::response(json_encode(['id' => 'r']), 201),
    ]);

    $connection = $this->registerProvisioningConnection(
        authScheme: AuthScheme::OAuth2ClientCredentials,
        secret: 'oauth-client-secret',
        authConfig: ['token_url' => 'https://idp.downstream.test/token', 'client_id' => 'client-abc'],
    )->connection;

    $client = app(ScimClient::class);

    // First op mints token-1; a second op within the TTL reuses it (one token fetch).
    $client->createUser($connection, ScimSchema::userResource('user-1', ['userName' => 'a@example.com']));
    $client->createUser($connection, ScimSchema::userResource('user-2', ['userName' => 'b@example.com']));

    // Past the token's lifetime, the next op must mint a fresh token.
    $this->travel(200)->seconds();
    $client->createUser($connection, ScimSchema::userResource('user-3', ['userName' => 'c@example.com']));

    $tokenFetches = Http::recorded(fn (Request $request): bool => $request->url() === 'https://idp.downstream.test/token');
    expect($tokenFetches)->toHaveCount(2);

    // The op after expiry presented the refreshed token, not the stale one.
    $lastCreate = Http::recorded(fn (Request $request): bool => str_contains($request->url(), '/Users'))->last();
    expect($lastCreate[0]->header('Authorization')[0])->toBe('Bearer token-2');
});

/**
 * The outbound SCIM client's SSRF pinning, which had no test at all.
 *
 * That absence is not theoretical: the call to `SafeScimUrl::pinnedOptions()` was
 * replaced with `[]` during this review's falsification work, swept into a commit, and
 * RELEASED — and the whole 30-test provisioning suite stayed green, because nothing
 * exercised it. A guard nothing asserts on is a guard that can leave without a sound.
 *
 * Pinning matters at DELIVERY time and not just at registration: registration resolves
 * the host once, and a DNS record that answers publicly then and privately later is the
 * rebind window this closes.
 */
it('refuses to deliver to a connection whose host fails the SSRF guard', function (): void {
    Http::fake();

    // Registered with the guard off (file-wide beforeEach), then enabled for delivery —
    // so this proves the DELIVERY-time check specifically, not the registration one.
    $connection = $this->registerProvisioningConnection(baseUrl: 'https://blocked.test/scim/v2')->connection;
    config(['cbox-id.provisioning.verify_url' => true]);

    $result = app(ScimClient::class)->createUser(
        $connection,
        ScimSchema::userResource('user-1', ['userName' => 'u@example.com', 'active' => true]),
    );

    // Nothing left the process, and the caller is told so in the terms it acts on: a
    // transport failure, which the outbox retries, rather than a success it would record.
    Http::assertNothingSent();
    expect($result->successful())->toBeFalse()
        ->and($result->transport)->toBeTrue();
});

/**
 * A pushed profile update must not blank the name parts it did not mention.
 *
 * RFC 7644 §3.5.2.3: a pathed `replace` of a COMPLEX attribute replaces the whole
 * attribute. So `{"op":"replace","path":"name","value":{"formatted":"…"}}` told the
 * downstream app that `name` is now exactly that object — and `givenName` and
 * `familyName` were wiped on every push, silently, with a 200.
 *
 * The inbound side found and fixed this same bug, with a comment explaining that Entra's
 * read-modify-write reconciliation then pushes the omission back over the stored values.
 * It was never mirrored outbound. Leaf paths (`name.formatted`) replace one sub-attribute
 * and leave its siblings alone.
 */
it('patches a name sub-attribute rather than replacing the whole complex attribute', function (): void {
    $operations = AttributeMapping::patchOperations([], ['name' => 'Alice Example', 'email' => 'alice@corp.test'], true);

    $paths = array_map(fn (array $op): string => (string) ($op['path'] ?? ''), $operations);

    expect($paths)->toContain('name.formatted')
        // No message argument — see below. `toContain` is variadic and reads a second
        // string as another needle, so `not->toContain($needle, $message)` passes on the
        // message's absence and never checks the needle. This guard was green regardless,
        // over a defect that shipped: a pathed replace on `name` silently wiped
        // givenName/familyName on every push and returned 200.
        ->and($paths)->not->toContain('name');
});

/**
 * A multi-valued attribute is the opposite case: `emails` is a LIST, and replacing it
 * whole is the only way a push can remove an address. Flattening must not descend into
 * one and start addressing `emails.0`.
 */
it('replaces a multi-valued attribute whole', function (): void {
    $operations = AttributeMapping::patchOperations(
        ['emails' => 'emails'],
        ['emails' => [['value' => 'a@corp.test', 'primary' => true]]],
        true,
    );

    $paths = array_map(fn (array $op): string => (string) ($op['path'] ?? ''), $operations);

    expect($paths)->toContain('emails')
        ->and(implode(' ', $paths))->not->toContain('emails.0');
});

/**
 * A rejected credential is worth retrying; a rejected REQUEST is not.
 *
 * 401 and 403 used to be terminal, so a rotated downstream bearer token drained every
 * queued operation into dead letters — a connection fixable in thirty seconds by pasting
 * a new token, with nothing left to retry by the time anyone did. Unlike the OAuth path,
 * which refreshes with an expiry margin, a static bearer gives no warning it has been
 * replaced.
 *
 * The asymmetry is the argument: retrying a genuinely revoked credential costs a bounded
 * number of identical failures and then exhausts, while dead-lettering a rotated one
 * costs a silent, unrecoverable divergence between the directory and the downstream app.
 */
it('treats a rejected credential as retryable and a bad request as final', function (int $status, bool $retryable): void {
    expect((new ScimResult($status, []))->transient())->toBe($retryable);
})->with([
    'unauthorized — the token may simply have rotated' => [401, true],
    'forbidden — same' => [403, true],
    'rate limited' => [429, true],
    'server error' => [500, true],
    'bad request — retrying sends the same broken body' => [400, false],
    'conflict — the caller must reconcile, not repeat' => [409, false],
    'not found — the caller recreates instead' => [404, false],
]);
