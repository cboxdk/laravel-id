<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\WebhookSignatureFixture;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookSigningSchemes;
use Cbox\Id\Webhooks\DatabaseWebhookRegistry;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\CboxWebhookSignature;
use Cbox\Id\Webhooks\Support\StandardWebhookSignature;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => false]));

/**
 * Per-endpoint signature schemes, end to end: what is minted at registration, what goes
 * on the wire, and that a receiver using only the shipped helper — or any Standard
 * Webhooks library — verifies it.
 */

/** @return list<Request> */
function sentWebhookRequests(): array
{
    return array_map(fn (array $pair): Request => $pair[0], Http::recorded()->all());
}

/** @return array<string, list<string>> */
function lowercasedHeaders(Request $request): array
{
    return array_change_key_case($request->headers(), CASE_LOWER);
}

it('keeps the Cbox scheme the default, with the secret and headers it always had', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    expect($registered->signatureScheme())->toBe(SignatureScheme::Cbox)
        ->and($registered->secret)->toMatch('/^[0-9a-f]{64}$/')
        ->and(DB::table('webhook_endpoints')->where('id', $registered->endpoint->id)->value('signature_scheme'))->toBe('cbox');

    app(WebhookDispatcher::class)->dispatch('user.created', ['n' => 1], 'org_a');

    $request = sentWebhookRequests()[0];
    $headers = lowercasedHeaders($request);

    // Byte-for-byte the fixture's format, and nothing from the other scheme.
    expect($request->header('X-Cbox-Signature')[0])
        ->toBe(WebhookSignatureFixture::expectedHeader($request->header('X-Cbox-Timestamp')[0], $request->body(), $registered->secret))
        ->and($headers)->not->toHaveKey('webhook-id')
        ->and($headers)->not->toHaveKey('webhook-signature')
        ->and($headers)->not->toHaveKey('webhook-timestamp');

    CboxWebhookSignature::verify($request->body(), $request->headers(), $registered->secret);
});

it('stores every pre-existing endpoint on the Cbox scheme through the column default', function (): void {
    // A row written without naming the column — an endpoint from before the migration,
    // or a host's own insert — is on the original scheme.
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);
    $id = (string) Str::ulid();

    DB::table('webhook_endpoints')->insert([
        'id' => $id,
        'environment_id' => $registered->endpoint->environment_id,
        'organization_id' => 'org_a',
        'url' => 'https://legacy.test/x',
        'secret_encrypted' => $registered->endpoint->secret_encrypted,
        'event_types' => json_encode(['user.created']),
        'status' => 'active',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(WebhookEndpoint::query()->findOrFail($id)->signature_scheme)->toBe(SignatureScheme::Cbox);
});

it('mints a whsec secret for a Standard Webhooks endpoint and delivers a spec-verifiable request', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created'], SignatureScheme::StandardWebhooks);

    expect($registered->signatureScheme())->toBe(SignatureScheme::StandardWebhooks)
        ->and($registered->secret)->toStartWith('whsec_')
        ->and(strlen((string) base64_decode(substr($registered->secret, 6), true)))->toBe(32)
        ->and($registered->endpoint->secret_encrypted)->not->toContain($registered->secret);

    app(WebhookDispatcher::class)->dispatch('user.created', ['n' => 1], 'org_a');

    $request = sentWebhookRequests()[0];
    $headers = lowercasedHeaders($request);
    $delivery = WebhookDelivery::query()->firstOrFail();

    // The receiver's side, using nothing but the helper and the revealed secret.
    StandardWebhookSignature::verify($request->body(), $request->headers(), $registered->secret);

    /** @var array<string, mixed> $body */
    $body = json_decode($request->body(), true, 512, JSON_THROW_ON_ERROR);

    expect($headers['webhook-id'][0])->toBe($delivery->id)
        ->and($body['delivery_id'])->toBe($delivery->id)
        ->and($headers['webhook-timestamp'][0])->toMatch('/^[1-9][0-9]*$/')
        ->and($headers['webhook-signature'][0])->toStartWith('v1,')
        ->and($headers['webhook-signature'][0])->not->toContain(' ')
        // Only the chosen scheme's headers.
        ->and($headers)->not->toHaveKey('x-cbox-signature')
        ->and($headers)->not->toHaveKey('x-cbox-timestamp')
        ->and($request->header('Content-Type')[0])->toStartWith('application/json')
        ->and($delivery->status)->toBe(DeliveryStatus::Delivered);

    // The envelope is the same shape on either scheme.
    expect(array_keys($body))->toBe(['type', 'sequence', 'data', 'delivery_id']);
});

it('fails verification of a delivered request whose body or timestamp was tampered with', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created'], SignatureScheme::StandardWebhooks);

    app(WebhookDispatcher::class)->dispatch('user.created', ['amount' => 10], 'org_a');

    $request = sentWebhookRequests()[0];
    $headers = lowercasedHeaders($request);

    expect(fn () => StandardWebhookSignature::verify(str_replace('10', '99', $request->body()), $headers, $registered->secret))
        ->toThrow(InvalidWebhookSignature::class, 'No webhook signature matched the payload.');

    $headers['webhook-timestamp'] = [(string) ((int) $headers['webhook-timestamp'][0] - 1)];

    expect(fn () => StandardWebhookSignature::verify($request->body(), $headers, $registered->secret))
        ->toThrow(InvalidWebhookSignature::class, 'No webhook signature matched the payload.');
});

it('keeps the same webhook-id across retries and re-signs each attempt with a fresh timestamp', function (): void {
    Http::fake(['*' => Http::sequence()->push('', 500)->push('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created'], SignatureScheme::StandardWebhooks);

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    $delivery = WebhookDelivery::query()->firstOrFail();
    expect($delivery->status)->toBe(DeliveryStatus::Failed);

    $this->travel(10)->minutes();
    $delivery->update(['next_retry_at' => now()->subMinute()]);
    app(WebhookDispatcher::class)->retryPending();

    [$first, $second] = sentWebhookRequests();

    expect(lowercasedHeaders($first)['webhook-id'][0])->toBe($delivery->id)
        ->and(lowercasedHeaders($second)['webhook-id'][0])->toBe($delivery->id)
        ->and((int) lowercasedHeaders($second)['webhook-timestamp'][0])
        ->toBeGreaterThan((int) lowercasedHeaders($first)['webhook-timestamp'][0])
        ->and($first->body())->toBe($second->body())
        ->and(WebhookDelivery::query()->firstOrFail()->status)->toBe(DeliveryStatus::Delivered);

    // The retry verifies at the time it was sent; the first attempt is now outside the
    // window and a replay of it is refused.
    StandardWebhookSignature::verify($second->body(), $second->headers(), $registered->secret, now: now()->getTimestamp());

    expect(fn () => StandardWebhookSignature::verify($first->body(), $first->headers(), $registered->secret, now: now()->getTimestamp()))
        ->toThrow(InvalidWebhookSignature::class, 'more than 300 seconds in the past');
});

it('gives deliveries to different endpoints different ids', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://one.test/x', ['user.created'], SignatureScheme::StandardWebhooks);
    $this->registerWebhook('org_a', 'https://two.test/x', ['user.created'], SignatureScheme::StandardWebhooks);

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    $ids = array_map(fn (Request $request): string => lowercasedHeaders($request)['webhook-id'][0], sentWebhookRequests());

    expect($ids)->toHaveCount(2)->and(array_unique($ids))->toHaveCount(2);
});

it('moves an existing endpoint between schemes without a new secret', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);
    $schemes = app(WebhookSigningSchemes::class);

    $changed = $schemes->changeSignatureScheme($registered->endpoint->id, 'org_a', SignatureScheme::StandardWebhooks);

    expect($changed?->signature_scheme)->toBe(SignatureScheme::StandardWebhooks)
        ->and(DB::table('webhook_endpoints')->where('id', $registered->endpoint->id)->value('signature_scheme'))->toBe('standard_webhooks');

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    // The owner converts the hex secret they already hold; nothing is revealed again.
    $whsec = 'whsec_'.base64_encode($registered->secret);
    expect(StandardWebhookSignature::secretFor($registered->secret))->toBe($whsec);
    StandardWebhookSignature::verify(sentWebhookRequests()[0]->body(), sentWebhookRequests()[0]->headers(), $whsec);

    // …and back again: the Cbox headers return, keyed by the same hex secret.
    $schemes->changeSignatureScheme($registered->endpoint->id, 'org_a', SignatureScheme::Cbox);
    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    $last = sentWebhookRequests()[1];
    expect(lowercasedHeaders($last))->not->toHaveKey('webhook-signature');
    CboxWebhookSignature::verify($last->body(), $last->headers(), $registered->secret);
});

it('signs a delivery under the scheme the endpoint has when it is sent', function (): void {
    Http::fake(['*' => Http::sequence()->push('', 500)->push('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);

    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');
    expect(lowercasedHeaders(sentWebhookRequests()[0]))->toHaveKey('x-cbox-signature');

    app(WebhookSigningSchemes::class)->changeSignatureScheme($registered->endpoint->id, 'org_a', SignatureScheme::StandardWebhooks);
    WebhookDelivery::query()->firstOrFail()->update(['next_retry_at' => now()->subMinute()]);
    app(WebhookDispatcher::class)->retryPending();

    $retry = sentWebhookRequests()[1];
    StandardWebhookSignature::verify($retry->body(), $retry->headers(), StandardWebhookSignature::secretFor($registered->secret));

    expect(lowercasedHeaders($retry))->not->toHaveKey('x-cbox-signature');
});

it('lets a whsec endpoint switched to the Cbox scheme verify with the literal whsec string', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created'], SignatureScheme::StandardWebhooks);

    app(WebhookSigningSchemes::class)->changeSignatureScheme($registered->endpoint->id, 'org_a', SignatureScheme::Cbox);
    app(WebhookDispatcher::class)->dispatch('user.created', [], 'org_a');

    $request = sentWebhookRequests()[0];
    CboxWebhookSignature::verify($request->body(), $request->headers(), $registered->secret);

    expect(true)->toBeTrue();
});

it('changes the scheme only for the exact owner', function (): void {
    $owned = $this->registerWebhook('org_a', 'https://hook.test/x', ['user.created']);
    $platform = $this->registerWebhook(null, 'https://global.test/x', ['user.created']);
    $schemes = app(WebhookSigningSchemes::class);

    // Another organization, and an organization reaching for the environment's endpoint.
    expect($schemes->changeSignatureScheme($owned->endpoint->id, 'org_b', SignatureScheme::StandardWebhooks))->toBeNull()
        ->and($schemes->changeSignatureScheme($owned->endpoint->id, null, SignatureScheme::StandardWebhooks))->toBeNull()
        ->and($schemes->changeSignatureScheme($platform->endpoint->id, 'org_a', SignatureScheme::StandardWebhooks))->toBeNull()
        ->and($schemes->changeSignatureScheme('01HF3QK9Z8VN0T7M2XW5RB4YCD', 'org_a', SignatureScheme::StandardWebhooks))->toBeNull();

    expect(WebhookEndpoint::query()->pluck('signature_scheme')->map->value->unique()->values()->all())->toBe(['cbox']);

    // The environment changes its own.
    expect($schemes->changeSignatureScheme($platform->endpoint->id, null, SignatureScheme::StandardWebhooks)?->signature_scheme)
        ->toBe(SignatureScheme::StandardWebhooks);
});

it('registers platform-wide Standard Webhooks endpoints, and binds the contract to the database registry', function (): void {
    $registered = app(WebhookSigningSchemes::class)
        ->registerForEnvironmentWithScheme('https://global.test/x', ['*'], SignatureScheme::StandardWebhooks);

    expect(app(WebhookSigningSchemes::class))->toBeInstanceOf(DatabaseWebhookRegistry::class)
        ->and($registered->endpoint->organization_id)->toBeNull()
        ->and($registered->signatureScheme())->toBe(SignatureScheme::StandardWebhooks)
        ->and($registered->secret)->toStartWith('whsec_');
});

it('takes the scheme as a trailing optional on the concrete registry', function (): void {
    $registered = app(DatabaseWebhookRegistry::class)
        ->register('org_a', 'https://hook.test/x', ['user.created'], SignatureScheme::StandardWebhooks);

    expect($registered->signatureScheme())->toBe(SignatureScheme::StandardWebhooks)
        ->and($registered->secret)->toStartWith('whsec_');
});
