<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\FineGrainedAuthorization;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidConsistencyToken;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidTuple;
use Cbox\Id\Kernel\Authorization\Exceptions\SchemaConflict;
use Cbox\Id\Kernel\Authorization\Exceptions\SchemaNotDefined;
use Cbox\Id\Kernel\Authorization\Exceptions\UnknownRelation;
use Cbox\Id\Kernel\Authorization\Fga\DatabaseTupleReader;
use Cbox\Id\Kernel\Authorization\Fga\Evaluator;
use Cbox\Id\Kernel\Authorization\Models\FgaStore;
use Cbox\Id\Kernel\Authorization\Models\FgaTuple;
use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use Cbox\Id\Kernel\Authorization\Schema\SchemaParser;
use Cbox\Id\Kernel\Authorization\ValueObjects\Check;
use Cbox\Id\Kernel\Authorization\ValueObjects\CheckResult;
use Cbox\Id\Kernel\Authorization\ValueObjects\ConsistencyToken;
use Cbox\Id\Kernel\Authorization\ValueObjects\ObjectList;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\SchemaState;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\TupleFilter;
use Cbox\Id\Kernel\Authorization\ValueObjects\TuplePage;
use Cbox\Id\Kernel\Authorization\ValueObjects\TupleWrite;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use JsonException;

/**
 * Fine-grained authorization over the database, with a revision-keyed cache in front of
 * every read.
 *
 * THE REVISION. Each environment's model has one monotonic counter ({@see FgaStore}),
 * advanced inside the same transaction as every write to it — a tuple batch or a schema
 * change. The store row is locked for that transaction, so writes to one environment are
 * serialized and every revision names exactly one committed state.
 *
 * THE CACHE. A read first loads the store row (one primary-key read: the revision, its
 * tag and the schema), then looks its answer up under
 * `cbox-fga:<environment>:<revision>:<tag>:<question>`. A write advances the revision, so
 * the next read asks a key nothing has answered yet: invalidation is immediate, atomic
 * across cache nodes, and needs no delete. Nothing is ever cached under a revision the
 * reader has not itself seen committed, and the tag makes a key computed inside a
 * rolled-back transaction unreachable. The price is that ANY write to an environment's
 * model cools that environment's whole cache — the right trade for a model read far more
 * than it is written; the benchmark notes in the docs measure it.
 *
 * "AT LEAST AS FRESH". A read given a consistency token compares the revision it loaded
 * with the token's; when the read connection is behind (a replica), the store row and
 * every tuple are re-read from the write connection. A token for a revision the
 * environment has not reached is refused, not waited for.
 *
 * Schemas are parsed once per content hash and kept in-process, so a check never parses.
 */
class DatabaseFineGrainedAuthorization implements FineGrainedAuthorization
{
    // Lazy per-call: this is a singleton, and the environment context is scoped.
    use ResolvesEnvironment;

    private const int SCHEMA_MEMO = 32;

    /** @var array<string, AuthorizationSchema> by schema hash */
    private array $schemas = [];

    public function __construct(private readonly CacheFactory $caches) {}

    public function schema(): SchemaState
    {
        $environmentId = $this->environmentId();
        $store = $this->store($environmentId, false);

        return $this->state($environmentId, $store);
    }

    public function validateSchema(string $source): AuthorizationSchema
    {
        return (new SchemaParser)->parse($source);
    }

    public function updateSchema(string $source): SchemaState
    {
        $schema = $this->validateSchema($source);
        $environmentId = $this->environmentId();

        return DB::transaction(function () use ($schema, $source, $environmentId): SchemaState {
            $store = $this->lockedStore($environmentId);
            $stranded = $this->stranded($schema, $environmentId);

            if ($stranded !== []) {
                throw new SchemaConflict($stranded);
            }

            $json = json_encode($schema->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

            $store->forceFill([
                'schema_source' => $source,
                'schema' => $json,
                'schema_hash' => hash('sha256', $json),
                'schema_version' => $store->schema_version + 1,
                'schema_updated_at' => Carbon::now(),
                'revision' => $store->revision + 1,
                'revision_tag' => self::tag(),
            ])->save();

            return $this->state($environmentId, $store);
        });
    }

    public function writeTuples(array $writes, array $deletes = []): TupleWrite
    {
        $environmentId = $this->environmentId();
        $max = $this->setting('max_batch', 100);

        if ($writes === [] && $deletes === []) {
            throw new InvalidTuple('A batch must write or delete at least one tuple.');
        }

        if (count($writes) + count($deletes) > $max) {
            throw new InvalidTuple("A batch may hold at most {$max} tuples.");
        }

        $deleting = [];

        foreach ($deletes as $tuple) {
            $deleting[$tuple->key()] = true;
        }

        foreach ($writes as $index => $tuple) {
            if (isset($deleting[$tuple->key()])) {
                throw new InvalidTuple('it is both written and deleted in the same batch.', $index);
            }
        }

        return DB::transaction(function () use ($environmentId, $writes, $deletes): TupleWrite {
            $store = $this->lockedStore($environmentId);
            $schema = $this->requireSchema($store);

            foreach ($writes as $index => $tuple) {
                $this->assertWritable($schema, $tuple, $index);
            }

            foreach ($deletes as $index => $tuple) {
                $this->assertWellFormed($tuple, $index);
            }

            $revision = $store->revision + 1;
            $now = Carbon::now();
            $rows = [];

            foreach ($writes as $tuple) {
                $rows[$tuple->key()] = [
                    'id' => strtolower((string) Str::ulid()),
                    'environment_id' => $environmentId,
                    'resource_type' => $tuple->resource->type,
                    'resource_id' => $tuple->resource->id,
                    'relation' => $tuple->relation,
                    'subject_type' => $tuple->subject->type,
                    'subject_id' => $tuple->subject->id,
                    'subject_relation' => $tuple->subject->relation ?? '',
                    'created_revision' => $revision,
                    'created_at' => $now,
                ];
            }

            $written = $rows === [] ? 0 : DB::table('fga_tuples')->insertOrIgnore(array_values($rows));
            $deleted = 0;

            foreach ($deletes as $tuple) {
                $deleted += FgaTuple::query()
                    ->where('environment_id', $environmentId)
                    ->where('resource_type', $tuple->resource->type)
                    ->where('resource_id', $tuple->resource->id)
                    ->where('relation', $tuple->relation)
                    ->where('subject_type', $tuple->subject->type)
                    ->where('subject_id', $tuple->subject->id)
                    ->where('subject_relation', $tuple->subject->relation ?? '')
                    ->toBase()
                    ->delete();
            }

            // Nothing changed — a re-write of what is there, a delete of what is not: the
            // model is at the same revision, and every cached answer still holds.
            if ($written + $deleted > 0) {
                $store->forceFill(['revision' => $revision, 'revision_tag' => self::tag()])->save();
            }

            return new TupleWrite($written, $deleted, ConsistencyToken::for($environmentId, $store->revision));
        });
    }

    public function tuples(TupleFilter $filter, int $limit = 50, ?string $after = null): TuplePage
    {
        $environmentId = $this->environmentId();
        $store = $this->store($environmentId, false);

        $rows = FgaTuple::query()
            ->where('environment_id', $environmentId)
            ->when($filter->resourceType !== null, static fn ($query) => $query->where('resource_type', $filter->resourceType))
            ->when($filter->resourceId !== null, static fn ($query) => $query->where('resource_id', $filter->resourceId))
            ->when($filter->relation !== null, static fn ($query) => $query->where('relation', $filter->relation))
            ->when($filter->subjectType !== null, static fn ($query) => $query->where('subject_type', $filter->subjectType))
            ->when($filter->subjectId !== null, static fn ($query) => $query->where('subject_id', $filter->subjectId))
            ->when($filter->subjectRelation !== null, static fn ($query) => $query->where('subject_relation', $filter->subjectRelation))
            ->when($after !== null, static fn ($query) => $query->where('id', '>', $after))
            ->orderBy('id')
            ->limit($limit + 1)
            ->get();

        $more = $rows->count() > $limit;
        $page = $rows->take($limit);
        $last = $page->last();

        return new TuplePage(
            array_values($page->map(static fn (FgaTuple $row): Tuple => $row->toTuple())->all()),
            $more && $last !== null ? $last->id : null,
            ConsistencyToken::for($environmentId, $store->revision ?? 0),
        );
    }

    public function check(Check $check, ConsistencyToken|string|null $consistency = null): CheckResult
    {
        return $this->checkMany([$check], $consistency)[0];
    }

    public function checkMany(array $checks, ConsistencyToken|string|null $consistency = null): array
    {
        $environmentId = $this->environmentId();
        [$store, $fresh] = $this->resolve($environmentId, $consistency);
        $schema = $this->requireSchema($store);

        foreach ($checks as $check) {
            $this->assertKnown($schema, $check->resource->type, $check->relation);
            $this->assertKnownSubject($schema, $check->subject);
        }

        $token = ConsistencyToken::for($environmentId, $store->revision);
        $keys = [];

        foreach ($checks as $index => $check) {
            $keys[$index] = $this->cacheKey($environmentId, $store, 'check', $check->key());
        }

        $cached = $this->cacheEnabled() && $keys !== [] ? $this->cache()->many(array_values(array_unique($keys))) : [];
        $evaluator = null;
        $results = [];
        $misses = [];

        foreach ($checks as $index => $check) {
            $hit = $cached[$keys[$index]] ?? null;

            if (is_int($hit) || is_bool($hit)) {
                $results[] = new CheckResult($check, (bool) $hit, $token);

                continue;
            }

            $evaluator ??= $this->evaluator($schema, $environmentId, $fresh);
            $allowed = $evaluator->check($check->resource->type, $check->resource->id, $check->relation, $check->subject);
            $misses[$keys[$index]] = $allowed ? 1 : 0;
            $results[] = new CheckResult($check, $allowed, $token);
        }

        if ($misses !== [] && $this->cacheEnabled()) {
            $this->cache()->putMany($misses, $this->ttl());
        }

        return $results;
    }

    public function listResources(SubjectRef $subject, string $relation, string $resourceType, ConsistencyToken|string|null $consistency = null, int $limit = 100, ?string $after = null): ObjectList
    {
        $environmentId = $this->environmentId();
        [$store, $fresh] = $this->resolve($environmentId, $consistency);
        $schema = $this->requireSchema($store);

        $this->assertKnown($schema, $resourceType, $relation);
        $this->assertKnownSubject($schema, $subject);

        $page = $this->remember(
            $this->cacheKey($environmentId, $store, 'resources', $resourceType.'#'.$relation.'@'.$subject.'|'.$limit.'|'.$after),
            fn (): array => $this->evaluator($schema, $environmentId, $fresh)->resources($subject, $relation, $resourceType, $limit, $after),
        );

        return $this->objects($resourceType, $page, $environmentId, $store);
    }

    public function listSubjects(ResourceRef $resource, string $relation, string $subjectType, ConsistencyToken|string|null $consistency = null, int $limit = 100, ?string $after = null): ObjectList
    {
        $environmentId = $this->environmentId();
        [$store, $fresh] = $this->resolve($environmentId, $consistency);
        $schema = $this->requireSchema($store);

        $this->assertKnown($schema, $resource->type, $relation);

        if ($schema->type($subjectType) === null) {
            throw UnknownRelation::type($subjectType);
        }

        $page = $this->remember(
            $this->cacheKey($environmentId, $store, 'subjects', $resource->type.':'.$resource->id.'#'.$relation.'@'.$subjectType.'|'.$limit.'|'.$after),
            fn (): array => $this->evaluator($schema, $environmentId, $fresh)->subjects($resource->type, $resource->id, $relation, $subjectType, $limit, $after),
        );

        return $this->objects($subjectType, $page, $environmentId, $store);
    }

    public function revision(): ConsistencyToken
    {
        $environmentId = $this->environmentId();

        return ConsistencyToken::for($environmentId, $this->store($environmentId, false)->revision ?? 0);
    }

    /**
     * The store row to evaluate against, and whether it (and the tuples) must be read
     * from the write connection to honour $consistency.
     *
     * @return array{0: FgaStore, 1: bool}
     *
     * @throws InvalidConsistencyToken
     * @throws SchemaNotDefined
     */
    private function resolve(string $environmentId, ConsistencyToken|string|null $consistency): array
    {
        $wanted = is_string($consistency) ? ConsistencyToken::parse($consistency, $environmentId) : $consistency;
        $store = $this->store($environmentId, false);
        $fresh = false;

        if ($wanted !== null && ($store->revision ?? 0) < $wanted->revision) {
            $store = $this->store($environmentId, true);
            $fresh = true;

            if (($store->revision ?? 0) < $wanted->revision) {
                throw new InvalidConsistencyToken('That consistency token names a revision this environment has not reached.');
            }
        }

        if ($store === null) {
            throw new SchemaNotDefined;
        }

        return [$store, $fresh];
    }

    private function store(string $environmentId, bool $fresh): ?FgaStore
    {
        $query = FgaStore::query()->where('environment_id', $environmentId);

        return ($fresh ? $query->useWritePdo() : $query)->first();
    }

    /**
     * The store row, created on first use, locked for the rest of the transaction — the
     * lock is what serializes writes to one environment's model and keeps its revision
     * gap-free.
     */
    private function lockedStore(string $environmentId): FgaStore
    {
        DB::table('fga_stores')->insertOrIgnore([
            'id' => strtolower((string) Str::ulid()),
            'environment_id' => $environmentId,
            'revision' => 0,
            'revision_tag' => self::tag(),
            'schema_version' => 0,
            'created_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);

        return FgaStore::query()->where('environment_id', $environmentId)->lockForUpdate()->firstOrFail();
    }

    private function state(string $environmentId, ?FgaStore $store): SchemaState
    {
        return new SchemaState(
            $store?->schema_source,
            $store === null || $store->schema === null ? null : $this->parsed($store),
            $store->schema_version ?? 0,
            ConsistencyToken::for($environmentId, $store->revision ?? 0),
            $store?->schema_updated_at,
        );
    }

    /**
     * @throws SchemaNotDefined
     */
    private function requireSchema(?FgaStore $store): AuthorizationSchema
    {
        if ($store === null || $store->schema === null) {
            throw new SchemaNotDefined;
        }

        return $this->parsed($store);
    }

    private function parsed(FgaStore $store): AuthorizationSchema
    {
        $hash = (string) $store->schema_hash;

        if (isset($this->schemas[$hash])) {
            return $this->schemas[$hash];
        }

        try {
            $data = json_decode((string) $store->schema, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $data = [];
        }

        if (count($this->schemas) >= self::SCHEMA_MEMO) {
            $this->schemas = [];
        }

        return $this->schemas[$hash] = AuthorizationSchema::fromArray(is_array($data) ? $data : []);
    }

    /**
     * The groups of stored tuples the new schema would no longer allow.
     *
     * @return list<array{resource_type: string, relation: string, subject: string, tuples: int}>
     */
    private function stranded(AuthorizationSchema $schema, string $environmentId): array
    {
        $groups = FgaTuple::query()
            ->where('environment_id', $environmentId)
            ->toBase()
            ->select(['resource_type', 'relation', 'subject_type', 'subject_relation', DB::raw('count(*) as tuples')])
            ->groupBy(['resource_type', 'relation', 'subject_type', 'subject_relation'])
            ->orderBy('resource_type')
            ->orderBy('relation')
            ->get();

        $stranded = [];

        foreach ($groups as $group) {
            /** @var object{resource_type: string, relation: string, subject_type: string, subject_relation: string, tuples: int|string} $group */
            $direct = $schema->relation($group->resource_type, $group->relation)?->directlyRelated();
            $subjectRelation = $group->subject_relation === '' ? null : $group->subject_relation;

            if ($direct === null || ! $direct->allows($group->subject_type, $subjectRelation)) {
                $stranded[] = [
                    'resource_type' => $group->resource_type,
                    'relation' => $group->relation,
                    'subject' => $group->subject_type.($subjectRelation === null ? '' : '#'.$subjectRelation),
                    'tuples' => (int) $group->tuples,
                ];
            }
        }

        return $stranded;
    }

    /**
     * @throws InvalidTuple
     */
    private function assertWritable(AuthorizationSchema $schema, Tuple $tuple, int $index): void
    {
        $this->assertWellFormed($tuple, $index);

        if ($schema->type($tuple->resource->type) === null) {
            throw new InvalidTuple("the schema defines no type `{$tuple->resource->type}`.", $index, 'resource_type');
        }

        $relation = $schema->relation($tuple->resource->type, $tuple->relation);

        if ($relation === null) {
            throw new InvalidTuple("`{$tuple->resource->type}` has no relation `{$tuple->relation}`.", $index, 'relation');
        }

        $direct = $relation->directlyRelated();

        if ($direct === null) {
            throw new InvalidTuple("`{$tuple->relation}` on `{$tuple->resource->type}` is computed from other relations, so no tuple can be written to it — write the relations it is computed from.", $index, 'relation');
        }

        if (! $direct->allows($tuple->subject->type, $tuple->subject->relation)) {
            $subject = $tuple->subject->type.($tuple->subject->relation === null ? '' : '#'.$tuple->subject->relation);
            $allowed = implode(', ', array_map(static fn ($type): string => $type->toDsl(), $direct->types));

            throw new InvalidTuple("`{$tuple->relation}` on `{$tuple->resource->type}` does not take `{$subject}` — it takes [{$allowed}].", $index, 'subject');
        }
    }

    /**
     * @throws InvalidTuple
     */
    private function assertWellFormed(Tuple $tuple, int $index): void
    {
        foreach (['resource_id' => $tuple->resource->id, 'subject_id' => $tuple->subject->id] as $field => $id) {
            if (preg_match(SubjectRef::ID_PATTERN, $id) !== 1 || $id === '*') {
                throw new InvalidTuple("`{$id}` is not a valid id: 1–128 printable characters without spaces, `#` or `@` (and `*` alone is reserved).", $index, $field);
            }
        }

        foreach (['resource_type' => $tuple->resource->type, 'relation' => $tuple->relation, 'subject_type' => $tuple->subject->type, 'subject_relation' => $tuple->subject->relation ?? 'x'] as $field => $name) {
            if (strlen($name) > 64) {
                throw new InvalidTuple("`{$field}` is longer than 64 characters.", $index, $field);
            }
        }
    }

    /**
     * @throws UnknownRelation
     */
    private function assertKnown(AuthorizationSchema $schema, string $type, string $relation): void
    {
        if ($schema->type($type) === null) {
            throw UnknownRelation::type($type);
        }

        if ($schema->relation($type, $relation) === null) {
            throw UnknownRelation::relation($type, $relation);
        }
    }

    /**
     * @throws UnknownRelation
     */
    private function assertKnownSubject(AuthorizationSchema $schema, SubjectRef $subject): void
    {
        if ($subject->relation !== null) {
            $this->assertKnown($schema, $subject->type, $subject->relation);

            return;
        }

        if ($schema->type($subject->type) === null) {
            throw UnknownRelation::type($subject->type);
        }
    }

    private function evaluator(AuthorizationSchema $schema, string $environmentId, bool $fresh): Evaluator
    {
        return new Evaluator(
            $schema,
            new DatabaseTupleReader($environmentId, $fresh),
            $this->setting('max_depth', 25),
            $this->setting('max_expansion', 50_000),
        );
    }

    /**
     * @param  callable(): array{ids: list<string>, more: bool}  $compute
     * @return array{ids: list<string>, more: bool}
     */
    private function remember(string $key, callable $compute): array
    {
        if (! $this->cacheEnabled()) {
            return $compute();
        }

        $hit = $this->cache()->get($key);

        if (is_array($hit) && isset($hit['ids'], $hit['more']) && is_array($hit['ids'])) {
            /** @var array{ids: list<string>, more: bool} $hit */
            return $hit;
        }

        $page = $compute();
        $this->cache()->put($key, $page, $this->ttl());

        return $page;
    }

    /**
     * @param  array{ids: list<string>, more: bool}  $page
     */
    private function objects(string $type, array $page, string $environmentId, FgaStore $store): ObjectList
    {
        $last = $page['ids'] === [] ? null : $page['ids'][count($page['ids']) - 1];

        return new ObjectList($type, $page['ids'], $page['more'] ? $last : null, ConsistencyToken::for($environmentId, $store->revision));
    }

    private function cacheKey(string $environmentId, FgaStore $store, string $kind, string $question): string
    {
        return 'cbox-fga:'.$environmentId.':'.$store->revision.':'.$store->revision_tag.':'.$kind.':'.hash('sha256', $question);
    }

    private function cache(): Cache
    {
        $store = config('cbox-id.fga.cache.store');

        return $this->caches->store(is_string($store) && $store !== '' ? $store : null);
    }

    private function cacheEnabled(): bool
    {
        return (bool) config('cbox-id.fga.cache.enabled', true);
    }

    private function ttl(): int
    {
        return $this->setting('cache.ttl', 3_600);
    }

    private function setting(string $key, int $default): int
    {
        $value = config('cbox-id.fga.'.$key, $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }

    private function environmentId(): string
    {
        return $this->environments()->requireEnvironment()->environmentKey();
    }

    private static function tag(): string
    {
        return bin2hex(random_bytes(8));
    }
}
