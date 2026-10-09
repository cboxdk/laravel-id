<?php

declare(strict_types=1);

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\FeatureFlags\Enums\EvaluationReason;
use Cbox\Id\FeatureFlags\ValueObjects\FlagRule;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Evaluation: the precedence (switched off → user → organization → rollout → default), and
 * the rollout bucket, which must be the same answer for the same subject every time, on
 * every replica, and reproducible by an SDK offline.
 */
it('pins the rollout bucket to sha256(key/identity), so an SDK can reproduce it', function (): void {
    // The documented formula, computed independently of FlagRule::bucket().
    $expected = fn (string $key, string $id): int => (int) (hexdec(substr(hash('sha256', $key.'/'.$id), 0, 8)) % 100);

    foreach (['user_1', 'user_2', '01J9Z8Y7X6W5V4T3S2R1Q0P9N8', '42'] as $id) {
        expect(FlagRule::bucket('new-dashboard', $id))->toBe($expected('new-dashboard', $id))
            ->and(FlagRule::bucket('new-dashboard', $id))->toBe(FlagRule::bucket('new-dashboard', $id));
    }

    // Salted by the flag key: the same subject lands in different buckets per flag.
    $differs = false;
    foreach (range(1, 20) as $n) {
        $differs = $differs || FlagRule::bucket('flag-a', "user_{$n}") !== FlagRule::bucket('flag-b', "user_{$n}");
    }
    expect($differs)->toBeTrue();
});

it('keeps a rollout stable and only ever adds people as the percentage rises', function (): void {
    $at = fn (int $percentage, string $id): bool => (new FlagRule('checkout-v2', true, false, $percentage, [], []))
        ->evaluate($id, null)->enabled;

    $inAtTen = 0;

    foreach (range(1, 2000) as $n) {
        $id = "user_{$n}";

        // Same question, same answer.
        expect($at(10, $id))->toBe($at(10, $id));

        if ($at(10, $id)) {
            $inAtTen++;
            expect($at(20, $id))->toBeTrue()
                ->and($at(100, $id))->toBeTrue();
        }

        expect($at(0, $id))->toBeFalse();
    }

    // Roughly ten percent of two thousand — a loose band, the hash is not a coin.
    expect($inAtTen)->toBeGreaterThan(140)->toBeLessThan(260);
});

it('applies the precedence: user over organization over rollout over default', function (): void {
    $rule = new FlagRule(
        key: 'beta',
        enabled: true,
        defaultValue: true,
        rolloutPercentage: 0,
        users: ['user_off' => false, 'user_on' => true],
        organizations: ['org_off' => false, 'org_on' => true],
    );

    // A user rule beats the organization's.
    expect($rule->evaluate('user_off', 'org_on'))
        ->enabled->toBeFalse()->reason->toBe(EvaluationReason::UserTarget)
        ->and($rule->evaluate('user_on', 'org_off'))
        ->enabled->toBeTrue()->reason->toBe(EvaluationReason::UserTarget);

    // The organization's rule beats rollout and default.
    expect($rule->evaluate('someone', 'org_off'))
        ->enabled->toBeFalse()->reason->toBe(EvaluationReason::OrganizationTarget)
        ->and($rule->evaluate('someone', 'org_on'))
        ->enabled->toBeTrue()->reason->toBe(EvaluationReason::OrganizationTarget);

    // Rollout at 0% matches nobody, so the default (on) answers.
    expect($rule->evaluate('someone', 'org_other'))
        ->enabled->toBeTrue()->reason->toBe(EvaluationReason::Default);

    // A rollout that matches beats a default that is off.
    $rollout = new FlagRule('beta', true, false, 100, [], []);
    expect($rollout->evaluate('someone', null))->enabled->toBeTrue()->reason->toBe(EvaluationReason::Rollout);

    // Switched off beats everything, the user rule included.
    $off = new FlagRule('beta', false, true, 100, ['user_on' => true], ['org_on' => true]);
    expect($off->evaluate('user_on', 'org_on'))->enabled->toBeFalse()->reason->toBe(EvaluationReason::Disabled);
});

it('buckets by organization when there is no user, and falls to the default with neither', function (): void {
    $rule = new FlagRule('org-rollout', true, false, 50, [], []);

    $orgIn = null;
    foreach (range(1, 50) as $n) {
        if (FlagRule::bucket('org-rollout', "org_{$n}") < 50) {
            $orgIn = "org_{$n}";
            break;
        }
    }

    expect($orgIn)->not->toBeNull()
        ->and($rule->evaluate(null, $orgIn))->reason->toBe(EvaluationReason::Rollout)
        ->and($rule->evaluate(null, null))->enabled->toBeFalse()->reason->toBe(EvaluationReason::Default);
});

it('answers off for a key the environment does not define', function (): void {
    $flags = app(FeatureFlags::class);

    expect($flags->isEnabled('never-defined', 'user_1', null))->toBeFalse()
        ->and($flags->evaluate('never-defined', 'user_1'))->reason->toBe(EvaluationReason::UnknownFlag);
});

it('returns the sorted keys that are on, and every answer with its reason', function (): void {
    $organization = $this->makeOrganization('Acme');

    $this->createFeatureFlag('zeta', defaultValue: true);
    $this->createFeatureFlag('alpha', FlagTargeting::organizations([$organization->id]));
    $this->createFeatureFlag('middle');
    $this->createFeatureFlag('killed', defaultValue: true, enabled: false);

    $flags = app(FeatureFlags::class);

    expect($flags->forSubject('user_1', $organization->id))->toBe(['alpha', 'zeta'])
        ->and($flags->forSubject('user_1', null))->toBe(['zeta']);

    $all = $flags->evaluateAll('user_1', $organization->id);

    expect(array_keys($all))->toBe(['alpha', 'killed', 'middle', 'zeta'])
        ->and($all['alpha']->reason)->toBe(EvaluationReason::OrganizationTarget)
        ->and($all['killed']->reason)->toBe(EvaluationReason::Disabled)
        ->and($all['middle']->toArray())->toBe(['key' => 'middle', 'enabled' => false, 'reason' => 'default']);

    $this->assertFeatureEnabled('alpha', 'user_1', $organization->id);
    $this->assertFeatureDisabled('alpha', 'user_1', null);
});
