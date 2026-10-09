<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags;

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\FeatureFlags\Enums\TargetType;
use Cbox\Id\FeatureFlags\Exceptions\InvalidFeatureFlag;
use Cbox\Id\FeatureFlags\Exceptions\UnknownFeatureFlag;
use Cbox\Id\FeatureFlags\Models\FeatureFlag;
use Cbox\Id\FeatureFlags\Models\FeatureFlagTarget;
use Cbox\Id\FeatureFlags\ValueObjects\FeatureFlagChanges;
use Cbox\Id\FeatureFlags\ValueObjects\FlagEvaluation;
use Cbox\Id\FeatureFlags\ValueObjects\FlagRule;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Cbox\Id\FeatureFlags\ValueObjects\NewFeatureFlag;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Organization\Contracts\Organizations;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Database-backed {@see FeatureFlags}, evaluated from one cached copy per environment.
 *
 * THE HOT PATH IS A CACHE READ. A token mint with the `feature_flags` scope, a UserInfo
 * call and an evaluation request all ask for every flag at once, so the environment's
 * whole set is compiled into plain arrays ({@see FlagRule::toArray()}) and cached under
 * ONE key; a question is then answered in memory. One key per environment rather than per
 * flag or per subject, because a single changed rule can change the answer for anyone,
 * and one key is something every write can forget exactly.
 *
 * Invalidation happens twice, deliberately: at the models (any save or delete of a flag or
 * a rule forgets the key, so no future write path can miss it), and once more after the
 * surrounding transaction commits. The second is what makes it correct under a caller's
 * transaction: forgetting only inside it leaves a window in which another request reads
 * the OLD rows — the new ones are not committed yet — and caches them for a whole TTL.
 */
class DatabaseFeatureFlags implements FeatureFlags
{
    // EnvironmentContext is `scoped` and this class a singleton: resolve it per call, or a
    // queue worker keys one environment's flags under another's (see the trait).
    use ResolvesEnvironment;

    /** A key: lowercase letters and digits, with `-`, `_` or `.` between them. */
    private const KEY_PATTERN = '/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/';

    public function __construct(
        private readonly AuditLog $audit,
        private readonly EventBus $events,
        private readonly Organizations $organizations,
        private readonly Subjects $subjects,
    ) {}

    public function all(): array
    {
        return array_values(FeatureFlag::query()->with('targets')->orderBy('key')->get()->all());
    }

    public function find(string $flagId): ?FeatureFlag
    {
        return FeatureFlag::query()->with('targets')->whereKey($flagId)->first();
    }

    public function findByKey(string $key): ?FeatureFlag
    {
        return FeatureFlag::query()->with('targets')->where('key', $key)->first();
    }

    public function create(NewFeatureFlag $flag, ?AuditActor $actor = null): FeatureFlag
    {
        $this->environments()->requireEnvironment();

        $key = trim($flag->key);

        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            throw InvalidFeatureFlag::key($key);
        }

        if (FeatureFlag::query()->where('key', $key)->exists()) {
            throw InvalidFeatureFlag::keyTaken($key);
        }

        $description = $this->description($flag->description);
        $this->assertTargeting($flag->targeting);

        $model = DB::transaction(function () use ($key, $description, $flag): FeatureFlag {
            $model = new FeatureFlag;
            $model->id = (string) Str::ulid();
            $model->fill([
                'key' => $key,
                'description' => $description,
                'enabled' => $flag->enabled,
                'default_value' => $flag->defaultValue,
                'rollout_percentage' => $flag->targeting->rolloutPercentage,
            ]);
            $model->save();

            $this->writeTargets($model, $flag->targeting);

            return $model;
        });

        $this->forgetAfterCommit();

        $model->load('targets');
        $targeting = $model->targeting();

        $this->events->emit(new DomainEvent('feature_flag.created', $this->payload($model)));

        $this->audit->record(new AuditEvent(
            action: 'feature_flag.created',
            actorType: ($actor ?? AuditActor::system())->type,
            actorId: $actor?->id,
            targetType: 'feature_flag',
            targetId: $model->id,
            context: [
                'key' => $model->key,
                'enabled' => $model->enabled,
                'default_value' => $model->default_value,
                'targeting' => $this->targetingDiff(FlagTargeting::none(), $targeting),
            ],
        ));

        return $model;
    }

    public function update(string $flagId, FeatureFlagChanges $changes, ?AuditActor $actor = null): FeatureFlag
    {
        $this->environments()->requireEnvironment();

        $model = $this->find($flagId) ?? throw UnknownFeatureFlag::forId($flagId);

        $description = $changes->changesDescription ? $this->description($changes->description) : $model->description;

        if ($changes->targeting !== null) {
            $this->assertTargeting($changes->targeting);
        }

        $before = [
            'description' => $model->description,
            'enabled' => $model->enabled,
            'default_value' => $model->default_value,
        ];
        $beforeTargeting = $model->targeting();

        DB::transaction(function () use ($model, $changes, $description): void {
            $model->fill([
                'description' => $description,
                'enabled' => $changes->enabled ?? $model->enabled,
                'default_value' => $changes->defaultValue ?? $model->default_value,
            ]);

            if ($changes->targeting !== null) {
                $model->rollout_percentage = $changes->targeting->rolloutPercentage;

                FeatureFlagTarget::query()->where('feature_flag_id', $model->id)->delete();
                $this->writeTargets($model, $changes->targeting);
            }

            if ($model->isDirty()) {
                $model->save();
            }
        });

        $this->forgetAfterCommit();

        $model->load('targets');

        $changed = [];
        $context = ['key' => $model->key];

        foreach (['description' => $model->description, 'enabled' => $model->enabled, 'default_value' => $model->default_value] as $field => $after) {
            if ($before[$field] !== $after) {
                $changed[] = $field;
                $context['changes'][$field] = ['from' => $before[$field], 'to' => $after];
            }
        }

        $targetingDiff = $this->targetingDiff($beforeTargeting, $model->targeting());

        if ($targetingDiff !== []) {
            $changed[] = 'targeting';
            $context['changes']['targeting'] = $targetingDiff;
        }

        if ($changed === []) {
            return $model;
        }

        $this->events->emit(new DomainEvent('feature_flag.updated', [...$this->payload($model), 'changed' => $changed]));

        $this->audit->record(new AuditEvent(
            action: 'feature_flag.updated',
            actorType: ($actor ?? AuditActor::system())->type,
            actorId: $actor?->id,
            targetType: 'feature_flag',
            targetId: $model->id,
            context: $context,
        ));

        return $model;
    }

    public function delete(string $flagId, ?AuditActor $actor = null): void
    {
        $this->environments()->requireEnvironment();

        $model = FeatureFlag::query()->whereKey($flagId)->first() ?? throw UnknownFeatureFlag::forId($flagId);

        DB::transaction(function () use ($model): void {
            FeatureFlagTarget::query()->where('feature_flag_id', $model->id)->delete();
            $model->delete();
        });

        $this->forgetAfterCommit();

        $this->events->emit(new DomainEvent('feature_flag.deleted', ['id' => $model->id, 'key' => $model->key]));

        $this->audit->record(new AuditEvent(
            action: 'feature_flag.deleted',
            actorType: ($actor ?? AuditActor::system())->type,
            actorId: $actor?->id,
            targetType: 'feature_flag',
            targetId: $model->id,
            context: ['key' => $model->key],
        ));
    }

    public function isEnabled(string $key, ?string $subjectId, ?string $organizationId = null): bool
    {
        return $this->evaluate($key, $subjectId, $organizationId)->enabled;
    }

    public function evaluate(string $key, ?string $subjectId, ?string $organizationId = null): FlagEvaluation
    {
        $rule = $this->rules()[$key] ?? null;

        return $rule === null ? FlagEvaluation::unknown($key) : $rule->evaluate($subjectId, $organizationId);
    }

    public function forSubject(?string $subjectId, ?string $organizationId = null): array
    {
        $on = [];

        foreach ($this->rules() as $key => $rule) {
            if ($rule->evaluate($subjectId, $organizationId)->enabled) {
                $on[] = $key;
            }
        }

        return $on;
    }

    public function evaluateAll(?string $subjectId, ?string $organizationId = null): array
    {
        $all = [];

        foreach ($this->rules() as $key => $rule) {
            $all[$key] = $rule->evaluate($subjectId, $organizationId);
        }

        return $all;
    }

    /**
     * The environment's compiled flags, keyed and sorted by key — from the cache, or built
     * and cached on a miss. Outside any environment there are no flags.
     *
     * @return array<string, FlagRule>
     */
    private function rules(): array
    {
        $environment = $this->environments()->current();

        if ($environment === null) {
            return [];
        }

        $ttl = $this->cacheTtl();

        $rows = $ttl > 0
            ? Cache::remember(FeatureFlag::cacheKey($environment->environmentKey()), $ttl, fn (): array => $this->compile())
            : $this->compile();

        $rules = [];

        foreach ($rows as $row) {
            $rule = FlagRule::fromArray($row);
            $rules[$rule->key] = $rule;
        }

        return $rules;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function compile(): array
    {
        return array_map(static fn (FeatureFlag $flag): array => $flag->rule()->toArray(), $this->all());
    }

    private function forgetAfterCommit(): void
    {
        $key = FeatureFlag::cacheKey($this->environments()->requireEnvironment()->environmentKey());

        Cache::forget($key);

        // Runs at once when there is no open transaction; otherwise once the caller's
        // commits — see the class docblock for the window this closes.
        DB::afterCommit(static function () use ($key): void {
            Cache::forget($key);
        });
    }

    private function writeTargets(FeatureFlag $flag, FlagTargeting $targeting): void
    {
        foreach ([TargetType::User->value => $targeting->users, TargetType::Organization->value => $targeting->organizations] as $type => $rules) {
            foreach ($rules as $id => $enabled) {
                FeatureFlagTarget::query()->create([
                    'id' => (string) Str::ulid(),
                    'feature_flag_id' => $flag->id,
                    'target_type' => $type,
                    'target_id' => (string) $id,
                    'enabled' => $enabled,
                ]);
            }
        }
    }

    /**
     * A rule may name only this environment's users and organizations. Naming another
     * environment's would target nobody here — and a "saved" answer would confirm the
     * foreign id exists, so it is refused the same as an id that exists nowhere.
     *
     * @throws InvalidFeatureFlag
     */
    private function assertTargeting(FlagTargeting $targeting): void
    {
        $percentage = $targeting->rolloutPercentage;

        if ($percentage !== null && ($percentage < 0 || $percentage > 100)) {
            throw InvalidFeatureFlag::percentage($percentage);
        }

        $limit = $this->maxRules();

        if ($targeting->ruleCount() > $limit) {
            throw InvalidFeatureFlag::tooManyRules($limit);
        }

        $organizationIds = array_map('strval', array_keys($targeting->organizations));

        if ($organizationIds !== []) {
            $missing = array_values(array_diff($organizationIds, array_keys($this->organizations->findMany($organizationIds))));

            if ($missing !== []) {
                throw InvalidFeatureFlag::unknownOrganizations($missing);
            }
        }

        $userIds = array_map('strval', array_keys($targeting->users));

        if ($userIds !== []) {
            $missing = array_values(array_diff($userIds, array_map('strval', array_keys($this->subjects->findMany($userIds)))));

            if ($missing !== []) {
                throw InvalidFeatureFlag::unknownUsers($missing);
            }
        }
    }

    private function description(?string $description): ?string
    {
        $description = $description === null ? null : trim($description);

        if ($description === null || $description === '') {
            return null;
        }

        if (mb_strlen($description) > 500) {
            throw InvalidFeatureFlag::description();
        }

        return $description;
    }

    /**
     * What changed between two rule sets, for the audit trail: per kind, the rules set
     * (added, or flipped) and the ids removed; the rollout as from/to. Empty when nothing
     * changed.
     *
     * @return array<string, mixed>
     */
    private function targetingDiff(FlagTargeting $before, FlagTargeting $after): array
    {
        $diff = [];

        foreach (['users' => [$before->users, $after->users], 'organizations' => [$before->organizations, $after->organizations]] as $kind => [$old, $new]) {
            $set = [];

            foreach ($new as $id => $enabled) {
                if (! array_key_exists($id, $old) || $old[$id] !== $enabled) {
                    $set[(string) $id] = $enabled;
                }
            }

            $removed = array_map('strval', array_keys(array_diff_key($old, $new)));

            if ($set !== [] || $removed !== []) {
                $diff[$kind] = array_filter(['set' => $set, 'removed' => $removed], static fn (array $part): bool => $part !== []);
            }
        }

        if ($before->rolloutPercentage !== $after->rolloutPercentage) {
            $diff['rollout_percentage'] = ['from' => $before->rolloutPercentage, 'to' => $after->rolloutPercentage];
        }

        return $diff;
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(FeatureFlag $flag): array
    {
        return [
            'id' => $flag->id,
            'key' => $flag->key,
            'enabled' => $flag->enabled,
            'default_value' => $flag->default_value,
            'rollout_percentage' => $flag->rollout_percentage,
        ];
    }

    private function cacheTtl(): int
    {
        $ttl = config('cbox-id.feature_flags.cache_ttl', 300);

        return is_numeric($ttl) ? (int) $ttl : 300;
    }

    private function maxRules(): int
    {
        $max = config('cbox-id.feature_flags.max_rules', 1000);

        return is_numeric($max) ? max(0, (int) $max) : 1000;
    }
}
