<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Scopes\TenantScope;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\Organization\Contracts\CustomerApiKeys;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\ApiKeyRefusal;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\Exceptions\CustomerApiKeyRefused;
use Cbox\Id\Organization\Exceptions\InvalidApiKeyPrefix;
use Cbox\Id\Organization\Models\CustomerApiKey;
use Cbox\Id\Organization\Models\UserApiToken;
use Cbox\Id\Organization\ValueObjects\ApiKeyActor;
use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;
use Cbox\Id\Organization\ValueObjects\IssuedCustomerApiKey;
use Cbox\Id\Organization\ValueObjects\NewCustomerApiKey;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * The fixture every test here starts from: an app (`ctx_live`) whose declared role
 * `Filer` carries `returns:read` + `returns:file`, and a holder who is an active Member
 * of an active organization and holds that role there.
 */
beforeEach(function (): void {
    // Before anything resolves the (singleton) service, so it is built with the fakes.
    $this->events = $this->fakeEvents();
    $this->audit = $this->fakeAudit();

    $this->holder = $this->makeUser()->id;
    $this->org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme',
        slug: 'acme-'.Str::lower(Str::random(6)),
        type: OrganizationType::Customer,
    ));
    app(Memberships::class)->add($this->org->id, $this->holder, MembershipRole::Member);

    $this->tax = $this->makeClient()->client;
    $this->enableCustomerApiKeys($this->tax->client_id, 'ctx_live');

    $roles = app(Roles::class);
    $this->filer = $roles->define(null, 'Filer', null, $this->tax->client_id);
    $roles->grantPermission(null, $this->filer->id, 'returns:read');
    $roles->grantPermission(null, $this->filer->id, 'returns:file');
    $roles->assign($this->org->id, $this->holder, $this->filer->id);
});

/**
 * @param  list<string>  $permissions
 */
function issueCustomerKey(object $test, array $permissions = ['returns:read'], ?DateTimeInterface $expiresAt = null, ?string $clientId = null): IssuedCustomerApiKey
{
    return app(CustomerApiKeys::class)->issue(new NewCustomerApiKey(
        organizationId: $test->org->id,
        userId: $test->holder,
        clientId: $clientId ?? $test->tax->client_id,
        permissions: $permissions,
        name: 'Accounting sync',
        expiresAt: $expiresAt,
    ));
}

function customerKeyRefusal(Closure $issue): ?CustomerApiKeyRefused
{
    try {
        $issue();
    } catch (CustomerApiKeyRefused $refused) {
        return $refused;
    }

    return null;
}

it('issues a key in the app\'s own format, shown once and stored only as a hash', function (): void {
    $issued = issueCustomerKey($this, ['returns:read', 'returns:read', 'returns:file']);

    expect($issued->plaintext)->toMatch('/^ctx_live_[A-Za-z0-9]{48}$/')
        ->and($issued->key->token_hash)->toBe(hash('sha256', $issued->plaintext))
        ->and($issued->key->prefix)->toBe(substr($issued->plaintext, 0, 13))
        ->and($issued->key->toArray())->not->toHaveKey('token_hash')
        ->and($issued->key->client_id)->toBe($this->tax->client_id)
        ->and($issued->key->organization_id)->toBe($this->org->id)
        ->and($issued->key->user_id)->toBe($this->holder)
        ->and($issued->key->permissions)->toBe(['returns:read', 'returns:file'])
        ->and($issued->key->expires_at)->toBeNull();

    // Nothing in the row can reproduce the key.
    $row = (array) DB::table('user_api_tokens')->where('id', $issued->key->id)->first();
    expect(implode('|', array_map(fn (mixed $value): string => is_scalar($value) ? (string) $value : '', $row)))
        ->not->toContain(substr($issued->plaintext, 13));
});

it('emits api_key.created and records who created it', function (): void {
    $issued = issueCustomerKey($this);

    $this->events->assertEmitted('api_key.created', fn (DomainEvent $event): bool => $event->payload['key_id'] === $issued->key->id
        && $event->payload['client_id'] === $this->tax->client_id
        && $event->organizationId === $this->org->id);

    $this->audit->assertRecorded('api_key.created', fn (AuditEvent $event): bool => $event->actorType === ActorType::User
        && $event->actorId === $this->holder
        && $event->targetId === $issued->key->id);
});

it('catalogues both key events for webhook subscribers', function (): void {
    expect(WebhookEventType::subscribable('api_key.created'))->toBeTrue()
        ->and(WebhookEventType::subscribable('api_key.revoked'))->toBeTrue();
});

/*
 * THE ISSUANCE CAP. A key can carry nothing its holder does not hold for the app.
 */
it('refuses a permission the holder does not hold', function (): void {
    $refused = customerKeyRefusal(fn () => issueCustomerKey($this, ['returns:read', 'returns:delete']));

    expect($refused?->reason)->toBe(ApiKeyRefusal::PermissionNotHeld)
        ->and($refused?->permissions)->toBe(['returns:delete'])
        ->and(CustomerApiKey::query()->withoutGlobalScopes()->count())->toBe(0);
})->group('security');

it('refuses a permission the holder holds only for a DIFFERENT app', function (): void {
    $ledger = $this->makeClient()->client;
    $roles = app(Roles::class);
    $bookkeeper = $roles->define(null, 'Bookkeeper', null, $ledger->client_id);
    $roles->grantPermission(null, $bookkeeper->id, 'ledger:write');
    $roles->assign($this->org->id, $this->holder, $bookkeeper->id);

    $refused = customerKeyRefusal(fn () => issueCustomerKey($this, ['ledger:write']));

    expect($refused?->reason)->toBe(ApiKeyRefusal::PermissionNotHeld)
        ->and($refused?->permissions)->toBe(['ledger:write']);
})->group('security');

it('refuses to issue for an app that has not declared a key prefix', function (): void {
    $plain = $this->makeClient()->client;

    expect(customerKeyRefusal(fn () => issueCustomerKey($this, [], clientId: $plain->client_id))?->reason)
        ->toBe(ApiKeyRefusal::KeysNotEnabled)
        ->and(customerKeyRefusal(fn () => issueCustomerKey($this, [], clientId: 'cid_nobody'))?->reason)
        ->toBe(ApiKeyRefusal::UnknownClient);
});

it('refuses a holder who is not an active member of an active organization with an active account', function (): void {
    $stranger = $this->makeUser()->id;

    expect(customerKeyRefusal(fn () => app(CustomerApiKeys::class)->issue(new NewCustomerApiKey($this->org->id, $stranger, $this->tax->client_id)))?->reason)
        ->toBe(ApiKeyRefusal::NotAMember);

    app(Subjects::class)->deactivate($this->holder);
    expect(customerKeyRefusal(fn () => issueCustomerKey($this, []))?->reason)->toBe(ApiKeyRefusal::HolderInactive);

    app(Organizations::class)->suspend($this->org->id, 'operator_1');
    expect(customerKeyRefusal(fn () => issueCustomerKey($this, []))?->reason)->toBe(ApiKeyRefusal::OrganizationInactive);
});

it('refuses an expiry that is not in the future', function (): void {
    expect(customerKeyRefusal(fn () => issueCustomerKey($this, [], now()->subSecond()))?->reason)->toBe(ApiKeyRefusal::ExpiryInPast);
});

it('verifies a live key for the app it is bound to', function (): void {
    $issued = issueCustomerKey($this, ['returns:read', 'returns:file'], now()->addDays(30)->startOfSecond());

    $verification = app(CustomerApiKeys::class)->verify($this->tax, $issued->plaintext);

    expect($verification->toArray())->toBe([
        'active' => true,
        'key_id' => $issued->key->id,
        'sub' => $this->holder,
        'org' => $this->org->id,
        'org_role' => 'member',
        'permissions' => ['returns:read', 'returns:file'],
        'client_id' => $this->tax->client_id,
        'expires_at' => $issued->key->expires_at?->utc()->toIso8601ZuluString(),
    ]);
});

/*
 * THE RE-CAP. The key's permissions are a ceiling; what the holder holds NOW decides.
 */
it('drops a permission from the key the moment the holder loses it', function (): void {
    $issued = issueCustomerKey($this, ['returns:read', 'returns:file']);

    // The role is swapped for one that only reads.
    $roles = app(Roles::class);
    $reader = $roles->define(null, 'Reader', null, $this->tax->client_id);
    $roles->grantPermission(null, $reader->id, 'returns:read');
    $roles->unassign($this->org->id, $this->holder, $this->filer->id);
    $roles->assign($this->org->id, $this->holder, $reader->id);

    $verification = app(CustomerApiKeys::class)->verify($this->tax, $issued->plaintext);

    expect($verification->active)->toBeTrue()
        ->and($verification->permissions)->toBe(['returns:read']);

    // …and gaining a permission later never widens a key that was not issued with it.
    $roles->grantPermission(null, $reader->id, 'returns:delete');

    expect(app(CustomerApiKeys::class)->verify($this->tax, $issued->plaintext)->permissions)->toBe(['returns:read']);
})->group('security');

/*
 * THE BINDING. Another app never sees a key it was not issued for — not even that it exists.
 */
it('answers inactive when a different app verifies the key', function (): void {
    $issued = issueCustomerKey($this);

    $other = $this->makeClient()->client;
    $this->enableCustomerApiKeys($other->client_id, 'other_live');

    expect(app(CustomerApiKeys::class)->verify($other, $issued->plaintext)->toArray())->toBe(['active' => false])
        ->and(app(CustomerApiKeys::class)->verify($this->tax, $issued->plaintext)->active)->toBeTrue();
})->group('security');

it('answers inactive for a revoked key and an expired key', function (): void {
    $keys = app(CustomerApiKeys::class);

    $revoked = issueCustomerKey($this);
    expect($keys->revoke($revoked->key->id, ApiKeyActor::user($this->holder)))->toBeTrue();

    $expiring = issueCustomerKey($this, expiresAt: now()->addHour());

    $this->travel(61)->minutes();

    expect($keys->verify($this->tax, $revoked->plaintext)->toArray())->toBe(['active' => false])
        ->and($keys->verify($this->tax, $expiring->plaintext)->toArray())->toBe(['active' => false]);
})->group('security');

it('answers inactive for anything that is not a live key', function (): void {
    $keys = app(CustomerApiKeys::class);

    expect($keys->verify($this->tax, '')->active)->toBeFalse()
        ->and($keys->verify($this->tax, 'ctx_live_'.str_repeat('a', 48))->active)->toBeFalse()
        ->and($keys->verify($this->tax, 'ctx_live_short')->active)->toBeFalse()
        ->and($keys->verify($this->tax, 'cbid_pat_'.str_repeat('a', 48))->active)->toBeFalse();
});

it('goes inactive when the holder leaves the organization, and stays so if they come back', function (): void {
    $issued = issueCustomerKey($this);
    $keys = app(CustomerApiKeys::class);

    app(Memberships::class)->remove($this->org->id, $this->holder);
    expect($keys->verify($this->tax, $issued->plaintext)->active)->toBeFalse();

    // Re-added later, with the same role: the old key belonged to the membership that ended.
    $this->travel(5)->seconds();
    app(Memberships::class)->add($this->org->id, $this->holder, MembershipRole::Member);
    app(Roles::class)->assign($this->org->id, $this->holder, $this->filer->id);

    expect($keys->verify($this->tax, $issued->plaintext)->active)->toBeFalse()
        // …while a key issued under the new membership works.
        ->and($keys->verify($this->tax, issueCustomerKey($this)->plaintext)->active)->toBeTrue();
})->group('security');

it('goes inactive when the organization is suspended or the holder deactivated', function (): void {
    $keys = app(CustomerApiKeys::class);
    $issued = issueCustomerKey($this);

    app(Subjects::class)->deactivate($this->holder);
    expect($keys->verify($this->tax, $issued->plaintext)->active)->toBeFalse();

    app(Subjects::class)->reactivate($this->holder);
    expect($keys->verify($this->tax, $issued->plaintext)->active)->toBeTrue();

    app(Organizations::class)->suspend($this->org->id, 'operator_1');
    expect($keys->verify($this->tax, $issued->plaintext)->active)->toBeFalse();
})->group('security');

it('stamps last_used_at at most once a minute', function (): void {
    $issued = issueCustomerKey($this);
    $keys = app(CustomerApiKeys::class);
    $lastUsed = fn (): mixed => DB::table('user_api_tokens')->where('id', $issued->key->id)->value('last_used_at');

    $this->freezeSecond();
    $keys->verify($this->tax, $issued->plaintext);
    $first = $lastUsed();

    $this->travel(30)->seconds();
    $keys->verify($this->tax, $issued->plaintext);
    expect($first)->not->toBeNull()
        ->and($lastUsed())->toBe($first);

    $this->travel(31)->seconds();
    $keys->verify($this->tax, $issued->plaintext);
    expect($lastUsed())->not->toBe($first);
});

it('revokes once, attributing the actor, and reports a second revocation as a no-op', function (): void {
    $issued = issueCustomerKey($this);
    $keys = app(CustomerApiKeys::class);

    expect($keys->revoke($issued->key->id, ApiKeyActor::service('envkey_1')))->toBeTrue()
        ->and($keys->revoke($issued->key->id, ApiKeyActor::service('envkey_1')))->toBeFalse()
        ->and($keys->revoke('01jnotakey0000000000000000', ApiKeyActor::system()))->toBeFalse();

    $revocations = array_filter($this->events->emitted, fn (DomainEvent $event): bool => $event->type === 'api_key.revoked');
    expect($revocations)->toHaveCount(1);

    $this->audit->assertRecorded('api_key.revoked', fn (AuditEvent $event): bool => $event->actorType === ActorType::Service
        && $event->actorId === 'envkey_1'
        && $event->targetId === $issued->key->id);
});

it('lists a holder\'s and an organization\'s keys, newest first, optionally per app', function (): void {
    $other = $this->makeClient()->client;
    $this->enableCustomerApiKeys($other->client_id, 'other_live');

    $first = issueCustomerKey($this);
    $second = issueCustomerKey($this, [], clientId: $other->client_id);

    $keys = app(CustomerApiKeys::class);

    expect($keys->forUser($this->org->id, $this->holder)->modelKeys())->toBe([$second->key->id, $first->key->id])
        ->and($keys->forUser($this->org->id, $this->holder, $this->tax->client_id)->modelKeys())->toBe([$first->key->id])
        ->and($keys->forOrganization($this->org->id, $other->client_id)->modelKeys())->toBe([$second->key->id])
        ->and($keys->find($first->key->id)?->id)->toBe($first->key->id);
});

/*
 * BACK-COMPAT. Personal tokens and customer keys share a table and never each other's rows.
 */
it('keeps personal tokens and customer keys apart in both directions', function (): void {
    app(Memberships::class)->changeRole($this->org->id, $this->holder, MembershipRole::Admin);
    $pat = app(UserApiTokens::class)->issue($this->org->id, $this->holder, 'CLI', TokenScope::Write);
    $key = issueCustomerKey($this);

    // The personal-token surface does not see the customer key…
    expect(app(UserApiTokens::class)->forUser($this->org->id, $this->holder)->modelKeys())->toBe([$pat->token->id])
        ->and(UserApiToken::query()->withoutGlobalScope(TenantScope::class)->whereKey($key->key->id)->exists())->toBeFalse();

    app(UserApiTokens::class)->revoke($this->org->id, $key->key->id);
    expect(app(CustomerApiKeys::class)->verify($this->tax, $key->plaintext)->active)->toBeTrue();

    // …and the customer-key surface does not see the personal token.
    expect(app(CustomerApiKeys::class)->find($pat->token->id))->toBeNull()
        ->and(app(CustomerApiKeys::class)->forUser($this->org->id, $this->holder)->modelKeys())->toBe([$key->key->id])
        ->and(app(CustomerApiKeys::class)->revoke($pat->token->id, ApiKeyActor::system()))->toBeFalse()
        ->and(app(UserApiTokens::class)->resolve($pat->plaintext)?->scope)->toBe(TokenScope::Write);
});

it('validates the key prefix format and keeps it unique within the environment', function (): void {
    expect(ApiKeyPrefix::of('ctx_live')->value)->toBe('ctx_live')
        ->and(ApiKeyPrefix::of('ab_test')->isTest())->toBeTrue()
        ->and(ApiKeyPrefix::tryFrom('Ctx_live'))->toBeNull()
        ->and(ApiKeyPrefix::tryFrom('c_live'))->toBeNull()
        ->and(ApiKeyPrefix::tryFrom('ctx_prod'))->toBeNull()
        ->and(ApiKeyPrefix::tryFrom('9tx_live'))->toBeNull()
        ->and(ApiKeyPrefix::tryFrom('abcdefghijklmnopq_live'))->toBeNull()
        ->and(fn () => ApiKeyPrefix::of('cbid_live'))->toThrow(InvalidApiKeyPrefix::class, 'reserved');

    $other = $this->makeClient()->client;

    expect(fn () => $this->enableCustomerApiKeys($other->client_id, 'ctx_live'))
        ->toThrow(InvalidApiKeyPrefix::class, 'already declared by another app');

    // Re-declaring your own prefix is not a conflict, and clearing it stops issuance.
    $this->enableCustomerApiKeys($this->tax->client_id, 'ctx_live');
    app(CustomerApiKeys::class)->setPrefix($this->tax->client_id, null);

    expect(Client::query()->whereKey($this->tax->id)->value('api_key_prefix'))->toBeNull()
        ->and(customerKeyRefusal(fn () => issueCustomerKey($this, []))?->reason)->toBe(ApiKeyRefusal::KeysNotEnabled);
});

it('keeps verifying issued keys after the app clears its prefix', function (): void {
    $issued = issueCustomerKey($this);

    app(CustomerApiKeys::class)->setPrefix($this->tax->client_id, null);

    expect(app(CustomerApiKeys::class)->verify($this->tax->fresh() ?? $this->tax, $issued->plaintext)->active)->toBeTrue();
});
