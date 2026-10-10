<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\FineGrainedAuthorization;
use Cbox\Id\Kernel\Authorization\Fga\Evaluator;
use Cbox\Id\Kernel\Authorization\Fga\InMemoryTupleReader;
use Cbox\Id\Kernel\Authorization\ValueObjects\Check;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Tests\Support\Fga\RandomModel;
use Cbox\Id\Tests\Support\Fga\ReferenceModel;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
| THE EVALUATOR AGAINST THE REFERENCE, on random graphs.
|
| Each seed draws a valid schema (every rewrite kind, cycles and exclusions included) and
| a dense tuple graph, then asks every check, every list-resources and every list-subjects
| the universe allows of both the evaluator and {@see ReferenceModel}, a bottom-up
| fixpoint that shares no code with it. Any disagreement names the seed, the schema and
| the question, so it reproduces exactly.
*/

/**
 * @return list<string> every disagreement, described
 */
function fgaDisagreements(RandomModel $model, Closure $check, Closure $resources, Closure $subjects): array
{
    $reference = new ReferenceModel($model->schema, $model->ids(), $model->tuples);
    $wrong = [];

    foreach (RandomModel::TYPES as $type) {
        foreach (array_keys($model->schema->types[$type]->relations) as $relation) {
            foreach (RandomModel::IDS as $id) {
                foreach (RandomModel::USERS as $user) {
                    $expected = $reference->allows($type, $id, $relation, $user);

                    if ($check($type, $id, $relation, $user) !== $expected) {
                        $wrong[] = "check {$type}:{$id}#{$relation}@user:{$user} should be ".($expected ? 'true' : 'false');
                    }
                }

                if (($got = $subjects($type, $id, $relation)) !== ($want = $reference->users($type, $id, $relation))) {
                    $wrong[] = "subjects of {$type}:{$id}#{$relation}: got [".implode(',', $got).'], want ['.implode(',', $want).']';
                }
            }

            foreach (RandomModel::USERS as $user) {
                if (($got = $resources($user, $relation, $type)) !== ($want = $reference->resources($user, $relation, $type))) {
                    $wrong[] = "{$type} resources user:{$user} has {$relation} on: got [".implode(',', $got).'], want ['.implode(',', $want).']';
                }
            }
        }
    }

    return $wrong;
}

it('agrees with the reference fixpoint on 300 random graphs (in memory)', function (): void {
    foreach (range(1, 300) as $seed) {
        $model = new RandomModel($seed);
        $reader = new InMemoryTupleReader($model->tuples);
        $evaluator = static fn (): Evaluator => new Evaluator($model->schema, $reader, maxDepth: 1_000, maxExpansion: 100_000);

        $wrong = fgaDisagreements(
            $model,
            static fn (string $type, string $id, string $relation, string $user): bool => $evaluator()->check($type, $id, $relation, SubjectRef::of('user', $user)),
            static fn (string $user, string $relation, string $type): array => $evaluator()->resources(SubjectRef::of('user', $user), $relation, $type, 1_000)['ids'],
            static fn (string $type, string $id, string $relation): array => $evaluator()->subjects($type, $id, $relation, 'user', 1_000)['ids'],
        );

        expect($wrong)->toBe([], "Seed {$seed}:\n{$model->source}\n".implode("\n", array_slice($wrong, 0, 5)));
    }
});

it('agrees with the reference through one evaluator shared by every question (memo across checks)', function (): void {
    foreach (range(301, 400) as $seed) {
        $model = new RandomModel($seed, 60);
        $shared = new Evaluator($model->schema, new InMemoryTupleReader($model->tuples), maxDepth: 1_000, maxExpansion: 100_000);

        $wrong = fgaDisagreements(
            $model,
            static fn (string $type, string $id, string $relation, string $user): bool => $shared->check($type, $id, $relation, SubjectRef::of('user', $user)),
            static fn (string $user, string $relation, string $type): array => $shared->resources(SubjectRef::of('user', $user), $relation, $type, 1_000)['ids'],
            static fn (string $type, string $id, string $relation): array => $shared->subjects($type, $id, $relation, 'user', 1_000)['ids'],
        );

        expect($wrong)->toBe([], "Seed {$seed}:\n{$model->source}\n".implode("\n", array_slice($wrong, 0, 5)));
    }
});

it('agrees with the reference through the database and the cache', function (): void {
    config(['cbox-id.fga.max_depth' => 1_000, 'cbox-id.fga.max_expansion' => 100_000]);

    foreach (range(1, 12) as $seed) {
        $model = new RandomModel($seed);
        $this->actingAsEnvironment('env_prop_'.$seed);
        $fga = app(FineGrainedAuthorization::class);
        $fga->updateSchema($model->source);
        $fga->writeTuples($model->tuples);

        // Twice: the second pass is answered from the cache.
        foreach ([1, 2] as $pass) {
            $wrong = fgaDisagreements(
                $model,
                static fn (string $type, string $id, string $relation, string $user): bool => $fga->check(Check::of($type, $id, $relation, SubjectRef::of('user', $user)))->allowed,
                static fn (string $user, string $relation, string $type): array => $fga->listResources(SubjectRef::of('user', $user), $relation, $type, limit: 1_000)->ids,
                static fn (string $type, string $id, string $relation): array => $fga->listSubjects(ResourceRef::of($type, $id), $relation, 'user', limit: 1_000)->ids,
            );

            expect($wrong)->toBe([], "Seed {$seed}, pass {$pass}:\n{$model->source}\n".implode("\n", array_slice($wrong, 0, 5)));
        }
    }
});
