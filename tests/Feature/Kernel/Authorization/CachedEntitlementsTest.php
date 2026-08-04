<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Runtime\RequestLifetime;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('reflects an entitlement change instantly on the next read (hot path)', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'free']), EntitlementSource::Billing);
    expect($reader->get('org_x', 'plan')?->string('tier'))->toBe('free');

    // A billing change — no token, no TTL to wait out.
    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);
    expect($reader->get('org_x', 'plan')?->string('tier'))->toBe('pro');
});

it('serves reads from cache and only refreshes when a write bumps the version', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_x', new EntitlementInput('seats', ['limit' => 10]), EntitlementSource::Billing);
    expect($reader->get('org_x', 'seats')?->int('limit'))->toBe(10); // now cached

    // Mutate the row behind the cache's back (raw, bypassing the tenant scope).
    DB::table('entitlements')->where('key', 'seats')->update(['value' => json_encode(['limit' => 999])]);

    // Still served from cache — reads don't hit the DB on every call.
    expect($reader->get('org_x', 'seats')?->int('limit'))->toBe(10);

    // Any write to the org bumps its version → the next read is fresh.
    $writer->set('org_x', new EntitlementInput('feature.sso', ['enabled' => true]), EntitlementSource::Billing);
    expect($reader->get('org_x', 'seats')?->int('limit'))->toBe(999);
});

it('isolates the cache per environment for the same organization id, even when warm', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    // The SAME organization id in two environments. Org ids are ULIDs and the cache
    // prefix is app-global, so before the key carried the environment this was literally
    // the same string on both hosts — and the DB scope (Entitlement is environment-owned)
    // only protected the MISS path. The HIT path leaked.
    $organizationId = 'org_shared_id';

    $this->actingAsEnvironment('env_a');
    $writer->set($organizationId, new EntitlementInput('plan', ['tier' => 'enterprise']), EntitlementSource::Billing);

    // Warm env A's cache.
    expect($reader->get($organizationId, 'plan')?->string('tier'))->toBe('enterprise');

    // Env B granted this org nothing. A warm neighbour must not answer for it.
    $this->actingAsEnvironment('env_b');
    expect($reader->get($organizationId, 'plan'))->toBeNull()
        ->and($reader->all($organizationId))->toBe([]);

    // …and env A is undisturbed by the visit.
    $this->actingAsEnvironment('env_a');
    expect($reader->get($organizationId, 'plan')?->string('tier'))->toBe('enterprise');
});

it('does not resurrect a stale snapshot when the version counter is evicted', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_evict', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);
    expect($reader->get('org_evict', 'plan')?->string('tier'))->toBe('pro'); // value key warm

    $stale = Cache::get('cbox-ent:env_test:org_evict:'.Cache::get('cbox-ent-ver:env_test:org_evict'));
    expect($stale)->not->toBeNull();

    // The plan is cancelled: the row goes and the version bumps, orphaning the snapshot
    // above — which stays live in the store for the rest of its backstop TTL.
    $writer->revoke('org_evict', 'plan', EntitlementSource::Billing);
    expect($reader->get('org_evict', 'plan'))->toBeNull();

    // Now the counter is evicted. `allkeys-lru` evicts by recency, not TTL, and a tiny
    // integer counter is exactly the sort of key that goes; a bare INCR would also
    // recreate it low. Either way the counter restarts at a value it has ALREADY been
    // past, where an orphaned snapshot is still filed.
    Cache::forget('cbox-ent-ver:env_test:org_evict');
    Cache::put('cbox-ent:env_test:org_evict:0', $stale, 300);

    // The cancelled plan must stay cancelled — the class promises instant propagation,
    // so a lost counter has to fail closed (re-read), never re-address the old snapshot.
    expect($reader->get('org_evict', 'plan'))->toBeNull();
});

/**
 * The per-request memo is the one thing in this class that is not version-tagged, so it
 * is the one thing that could out-live an invalidation. It must not.
 *
 * This class is a SINGLETON and the host app decorates it inside another singleton, so
 * "per request" cannot mean "per instance" — under Octane the instance IS the worker. It
 * means the {@see RequestLifetime} token, which the container
 * replaces between requests and between queued jobs. Asserting BOTH halves: the memo
 * really does collapse repeat reads inside one request, and it really is gone at the next.
 */
it('does not let the per-request memo out-live the request', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_memo', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);
    expect($reader->get('org_memo', 'plan')?->string('tier'))->toBe('pro');

    // ANOTHER process cancels the plan: the row goes and the version is bumped, which is
    // all a second worker's write leaves behind for this one to notice.
    DB::table('entitlements')->where('key', 'plan')->delete();
    Cache::increment('cbox-ent-ver:env_test:org_memo');

    // Inside the same request the memo still answers — that is what makes eight
    // entitlement checks on one page cost two cache round trips instead of sixteen.
    expect($reader->get('org_memo', 'plan')?->string('tier'))->toBe('pro');

    // The request ends. Laravel drops scoped instances between requests and between
    // queued jobs; the memo has to go with them, or a cancellation would keep granting
    // for the life of the worker.
    app()->forgetScopedInstances();

    expect($reader->get('org_memo', 'plan'))->toBeNull();
});

it('isolates the cache per organization', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_a', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);
    $writer->set('org_b', new EntitlementInput('plan', ['tier' => 'free']), EntitlementSource::Billing);

    // A change to org_a must not disturb org_b's cached view.
    $writer->set('org_a', new EntitlementInput('plan', ['tier' => 'enterprise']), EntitlementSource::Billing);

    expect($reader->get('org_a', 'plan')?->string('tier'))->toBe('enterprise')
        ->and($reader->get('org_b', 'plan')?->string('tier'))->toBe('free');
});
