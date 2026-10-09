<?php

declare(strict_types=1);

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\FeatureFlags\Exceptions\InvalidFeatureFlag;
use Cbox\Id\FeatureFlags\Exceptions\UnknownFeatureFlag;
use Cbox\Id\FeatureFlags\Models\FeatureFlag;
use Cbox\Id\FeatureFlags\Models\FeatureFlagTarget;
use Cbox\Id\FeatureFlags\ValueObjects\FeatureFlagChanges;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Cbox\Id\FeatureFlags\ValueObjects\NewFeatureFlag;
use Cbox\Id\Identity\Contracts\SubjectEraser;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function flags(): FeatureFlags
{
    return app(FeatureFlags::class);
}

it('creates a flag that is live and off by default, with its rules', function (): void {
    $acme = $this->makeOrganization('Acme');
    $user = $this->makeUser('ada@example.com');

    $flag = flags()->create(new NewFeatureFlag(
        key: 'new-dashboard',
        description: '  The redesigned dashboard  ',
        targeting: new FlagTargeting([$user->id => true], [$acme->id => true], 25),
    ));

    expect($flag->key)->toBe('new-dashboard')
        ->and($flag->description)->toBe('The redesigned dashboard')
        ->and($flag->enabled)->toBeTrue()
        ->and($flag->default_value)->toBeFalse()
        ->and($flag->rollout_percentage)->toBe(25)
        ->and($flag->targeting()->users)->toBe([$user->id => true])
        ->and($flag->targeting()->organizations)->toBe([$acme->id => true])
        ->and(flags()->findByKey('new-dashboard')?->id)->toBe($flag->id);
});

it('refuses a malformed key, a taken key and an out-of-range rollout', function (): void {
    foreach (['', 'Upper', 'has space', '-leading', 'trailing-', str_repeat('a', 65)] as $key) {
        expect(fn () => flags()->create(new NewFeatureFlag($key)))
            ->toThrow(InvalidFeatureFlag::class);
    }

    flags()->create(new NewFeatureFlag('billing.v2'));

    try {
        flags()->create(new NewFeatureFlag('billing.v2'));
        $this->fail('a taken key was accepted');
    } catch (InvalidFeatureFlag $refused) {
        expect($refused->reason)->toBe('key_taken')->and($refused->field)->toBe('key');
    }

    expect(fn () => flags()->create(new NewFeatureFlag('ramp', targeting: FlagTargeting::rollout(101))))
        ->toThrow(InvalidFeatureFlag::class, 'rollout percentage');
});

it('refuses rules naming a user or organization the environment does not have', function (): void {
    try {
        flags()->create(new NewFeatureFlag('ghost', targeting: FlagTargeting::organizations(['01JNOSUCHORGANIZATION00000'])));
        $this->fail('an unknown organization was accepted');
    } catch (InvalidFeatureFlag $refused) {
        expect($refused->reason)->toBe('unknown_organization');
    }

    try {
        flags()->create(new NewFeatureFlag('ghost', targeting: FlagTargeting::users(['no-such-user'])));
        $this->fail('an unknown user was accepted');
    } catch (InvalidFeatureFlag $refused) {
        expect($refused->reason)->toBe('unknown_user');
    }

    expect(FeatureFlag::query()->count())->toBe(0);
});

it('caps the rules on one flag', function (): void {
    config()->set('cbox-id.feature_flags.max_rules', 1);

    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');

    expect(fn () => flags()->create(new NewFeatureFlag('wide', targeting: FlagTargeting::organizations([$a->id, $b->id]))))
        ->toThrow(InvalidFeatureFlag::class, 'at most 1');
});

it('changes only what it is told, and replaces targeting whole', function (): void {
    $acme = $this->makeOrganization('Acme');
    $globex = $this->makeOrganization('Globex');

    $flag = flags()->create(new NewFeatureFlag('beta', description: 'Kept', targeting: new FlagTargeting([], [$acme->id => true], 10)));

    $updated = flags()->update($flag->id, FeatureFlagChanges::make()->withEnabled(false));

    expect($updated->enabled)->toBeFalse()
        ->and($updated->description)->toBe('Kept')
        ->and($updated->rollout_percentage)->toBe(10)
        ->and($updated->targeting()->organizations)->toBe([$acme->id => true]);

    $updated = flags()->update($flag->id, FeatureFlagChanges::make()->withTargeting(FlagTargeting::organizations([$globex->id])));

    expect($updated->targeting()->organizations)->toBe([$globex->id => true])
        ->and($updated->rollout_percentage)->toBeNull()
        ->and(FeatureFlagTarget::query()->count())->toBe(1);

    expect(fn () => flags()->update('01JNOSUCHFLAG0000000000000', FeatureFlagChanges::make()->withEnabled(true)))
        ->toThrow(UnknownFeatureFlag::class);
});

it('announces and audits every change, with the actor the caller names, and not a change that changes nothing', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    app()->forgetInstance(FeatureFlags::class);

    $acme = $this->makeOrganization('Acme');
    $actor = AuditActor::organizationMember('member-1');

    $flag = flags()->create(new NewFeatureFlag('beta'), $actor);

    $events->assertEmitted('feature_flag.created', fn (DomainEvent $event): bool => $event->payload === [
        'id' => $flag->id, 'key' => 'beta', 'enabled' => true, 'default_value' => false, 'rollout_percentage' => null,
    ] && $event->organizationId === null);
    $audit->assertRecorded('feature_flag.created', fn (AuditEvent $event): bool => $event->actorType === ActorType::OrganizationMember
        && $event->actorId === 'member-1' && $event->targetId === $flag->id);

    flags()->update($flag->id, FeatureFlagChanges::make()->withDefaultValue(false)->withDescription(null), $actor);
    $events->assertNotEmitted('feature_flag.updated');
    $audit->assertNotRecorded('feature_flag.updated');

    flags()->update($flag->id, FeatureFlagChanges::make()->withTargeting(FlagTargeting::organizations([$acme->id]))->withDefaultValue(true), $actor);

    $events->assertEmitted('feature_flag.updated', fn (DomainEvent $event): bool => $event->payload['changed'] === ['default_value', 'targeting']);
    $audit->assertRecorded('feature_flag.updated', fn (AuditEvent $event): bool => $event->context['changes'] === [
        'default_value' => ['from' => false, 'to' => true],
        'targeting' => ['organizations' => ['set' => [$acme->id => true]]],
    ]);

    flags()->delete($flag->id, $actor);

    $events->assertEmitted('feature_flag.deleted', fn (DomainEvent $event): bool => $event->payload === ['id' => $flag->id, 'key' => 'beta']);
    $audit->assertRecorded('feature_flag.deleted');
});

it('deletes a flag with its rules, after which its key is off', function (): void {
    $acme = $this->makeOrganization('Acme');
    $flag = $this->createFeatureFlag('beta', FlagTargeting::organizations([$acme->id]));

    $this->assertFeatureEnabled('beta', null, $acme->id);

    flags()->delete($flag->id);

    expect(FeatureFlag::query()->count())->toBe(0)
        ->and(FeatureFlagTarget::query()->count())->toBe(0);
    $this->assertFeatureDisabled('beta', null, $acme->id);

    expect(fn () => flags()->delete($flag->id))->toThrow(UnknownFeatureFlag::class);
});

it('serves evaluation from the cache and forgets it on every change', function (): void {
    config()->set('cbox-id.feature_flags.cache_ttl', 3600);
    $acme = $this->makeOrganization('Acme');
    $flag = $this->createFeatureFlag('beta');

    $this->assertFeatureDisabled('beta', 'user_1', $acme->id);
    expect(Cache::has(FeatureFlag::cacheKey('env_test')))->toBeTrue();

    // Served from the cache: no query once it is warm.
    DB::enableQueryLog();
    flags()->forSubject('user_1', $acme->id);
    expect(collect(DB::getQueryLog())->filter(fn (array $q): bool => str_contains($q['query'], 'feature_flag')))->toBeEmpty();
    DB::disableQueryLog();

    // A change through the service is seen at once.
    flags()->update($flag->id, FeatureFlagChanges::make()->withTargeting(FlagTargeting::organizations([$acme->id])));
    $this->assertFeatureEnabled('beta', 'user_1', $acme->id);

    // So is one made straight on a model — the invalidation lives on the models.
    $this->assertFeatureEnabled('beta', 'user_1', $acme->id);
    FeatureFlag::query()->whereKey($flag->id)->firstOrFail()->update(['enabled' => false]);
    $this->assertFeatureDisabled('beta', 'user_1', $acme->id);
});

it('forgets the cache again once a surrounding transaction commits', function (): void {
    config()->set('cbox-id.feature_flags.cache_ttl', 3600);
    $flag = $this->createFeatureFlag('beta');

    DB::transaction(function () use ($flag): void {
        flags()->update($flag->id, FeatureFlagChanges::make()->withDefaultValue(true));

        // A reader warming the cache mid-transaction (here, the same connection) …
        flags()->forSubject('user_1');
        Cache::put(FeatureFlag::cacheKey('env_test'), [], 3600);
    });

    // … does not leave its copy behind: the commit forgot it.
    expect(Cache::has(FeatureFlag::cacheKey('env_test')))->toBeFalse();
    $this->assertFeatureEnabled('beta', 'user_1');
});

it('keeps each environment\'s flags, rules and cache to itself', function (): void {
    [$flagId, $acmeId] = $this->runAsEnvironment('env_a', function (): array {
        $acme = $this->makeOrganization('Acme');
        $flag = $this->createFeatureFlag('beta', FlagTargeting::organizations([$acme->id]));
        $this->assertFeatureEnabled('beta', null, $acme->id);

        return [$flag->id, $acme->id];
    });

    $this->runAsEnvironment('env_b', function () use ($flagId, $acmeId): void {
        // Invisible by id and by key, and evaluates as unknown.
        expect(flags()->find($flagId))->toBeNull()
            ->and(flags()->findByKey('beta'))->toBeNull()
            ->and(flags()->all())->toBe([])
            ->and(flags()->forSubject(null, $acmeId))->toBe([]);

        // Not changeable from here.
        expect(fn () => flags()->update($flagId, FeatureFlagChanges::make()->withEnabled(false)))->toThrow(UnknownFeatureFlag::class);
        expect(fn () => flags()->delete($flagId))->toThrow(UnknownFeatureFlag::class);

        // The same key is free here, and a rule naming env_a's organization is refused.
        $this->createFeatureFlag('beta', defaultValue: true);
        expect(fn () => flags()->create(new NewFeatureFlag('other', targeting: FlagTargeting::organizations([$acmeId]))))
            ->toThrow(InvalidFeatureFlag::class, 'No organization');
        expect(flags()->forSubject(null, $acmeId))->toBe(['beta']);
    });

    $this->runAsEnvironment('env_a', function () use ($acmeId): void {
        expect(flags()->evaluate('beta', null, $acmeId)->reason->value)->toBe('organization_target')
            ->and(flags()->forSubject(null, null))->toBe([]);
    });
})->group('isolation');

it('erases the rules that name an erased user', function (): void {
    config()->set('cbox-id.feature_flags.cache_ttl', 3600);
    $user = $this->makeUser('erase-me@example.com');
    $other = $this->makeUser('stays@example.com');

    $this->createFeatureFlag('beta', FlagTargeting::users([$user->id, $other->id]));
    $this->assertFeatureEnabled('beta', $user->id);

    $receipt = app(SubjectEraser::class)->erase($user->id);

    expect(FeatureFlagTarget::query()->pluck('target_id')->all())->toBe([$other->id])
        ->and(array_column($receipt->toArray()['steps'], 'counts', 'step')['feature_flags.targets'] ?? null)->toBe(['feature_flag_targets' => 1]);
    $this->assertFeatureDisabled('beta', $user->id);
    $this->assertFeatureEnabled('beta', $other->id);
});
