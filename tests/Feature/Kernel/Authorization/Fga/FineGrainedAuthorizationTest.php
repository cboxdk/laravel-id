<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\FineGrainedAuthorization;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidConsistencyToken;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidSchema;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidTuple;
use Cbox\Id\Kernel\Authorization\Exceptions\ResolutionTooComplex;
use Cbox\Id\Kernel\Authorization\Exceptions\SchemaConflict;
use Cbox\Id\Kernel\Authorization\Exceptions\SchemaNotDefined;
use Cbox\Id\Kernel\Authorization\Exceptions\UnknownRelation;
use Cbox\Id\Kernel\Authorization\Models\FgaStore;
use Cbox\Id\Kernel\Authorization\Models\FgaTuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\Check;
use Cbox\Id\Kernel\Authorization\ValueObjects\ConsistencyToken;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\TupleFilter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
| Fine-grained authorization over the database: checks with inheritance, list queries,
| tuple validation, schema changes that would strand tuples, one environment never
| seeing another's, consistency tokens, and a cache that is never stale.
*/

const FGA_FOLDERS = <<<'SCHEMA'
    type user

    type group
      relation member: [user, group#member]

    type folder
      relation parent: [folder]
      relation owner: [user]
      relation editor: [user, group#member] or owner or editor from parent
      relation viewer: [user, group#member] or editor or viewer from parent

    type document
      relation parent: [folder]
      relation owner: [user]
      relation editor: [user, group#member] or owner or editor from parent
      relation viewer: [user, group#member] or editor or viewer from parent
      relation blocked: [user]
      relation can_read: viewer but not blocked
      relation can_share: owner and can_read
    SCHEMA;

beforeEach(function (): void {
    $this->actingAsEnvironment('env_fga');
});

function fgaFolders(): void
{
    test()->fgaSchema(FGA_FOLDERS);
    test()->fgaWrite(
        'folder:handbook#owner@user:olivia',
        'folder:policies#parent@folder:handbook',
        'document:leave#parent@folder:policies',
        'group:eng#member@user:alice',
        'group:staff#member@group:eng#member',
        'folder:policies#viewer@group:staff#member',
        'document:leave#editor@user:bob',
        'document:salaries#owner@user:carol',
    );
}

it('inherits through computed relations and parent folders, levels deep', function (): void {
    fgaFolders();

    // olivia owns the top folder: owner → editor → viewer, down two parent hops.
    expect($this->fgaAllows('document:leave#viewer@user:olivia'))->toBeTrue()
        ->and($this->fgaAllows('document:leave#editor@user:olivia'))->toBeTrue()
        ->and($this->fgaAllows('document:leave#owner@user:olivia'))->toBeFalse()
        // alice: member of eng, eng's members are staff, staff view the policies folder.
        ->and($this->fgaAllows('document:leave#viewer@user:alice'))->toBeTrue()
        ->and($this->fgaAllows('document:leave#editor@user:alice'))->toBeFalse()
        ->and($this->fgaAllows('folder:handbook#viewer@user:alice'))->toBeFalse()
        // bob edits one document and nothing else.
        ->and($this->fgaAllows('document:leave#viewer@user:bob'))->toBeTrue()
        ->and($this->fgaAllows('folder:policies#viewer@user:bob'))->toBeFalse()
        // Nobody inherits from a document they have no path to.
        ->and($this->fgaAllows('document:salaries#viewer@user:olivia'))->toBeFalse()
        ->and($this->fgaAllows('document:salaries#viewer@user:carol'))->toBeTrue();
});

it('checks a userset as the subject — are all of eng\'s members viewers?', function (): void {
    fgaFolders();

    expect($this->fgaAllows('document:leave#viewer@group:eng#member'))->toBeTrue()
        ->and($this->fgaAllows('group:eng#member@group:eng#member'))->toBeTrue()
        ->and($this->fgaAllows('folder:handbook#viewer@group:eng#member'))->toBeFalse();
});

it('decides intersection and exclusion', function (): void {
    fgaFolders();
    $this->fgaWrite('document:salaries#blocked@user:carol', 'document:leave#blocked@user:alice');

    expect($this->fgaAllows('document:leave#can_read@user:alice'))->toBeFalse()
        ->and($this->fgaAllows('document:leave#can_read@user:bob'))->toBeTrue()
        // carol owns salaries but is blocked from it: owner AND can_read fails.
        ->and($this->fgaAllows('document:salaries#can_share@user:carol'))->toBeFalse();

    $this->fgaDelete('document:salaries#blocked@user:carol');

    expect($this->fgaAllows('document:salaries#can_share@user:carol'))->toBeTrue();
});

it('terminates on cyclic groups and folder loops, and still finds the grant', function (): void {
    $this->fgaSchema(FGA_FOLDERS);
    $this->fgaWrite(
        'group:a#member@group:b#member',
        'group:b#member@group:a#member',
        'group:b#member@user:zoe',
        'folder:x#parent@folder:y',
        'folder:y#parent@folder:x',
        'folder:y#viewer@group:a#member',
    );

    expect($this->fgaAllows('folder:x#viewer@user:zoe'))->toBeTrue()
        ->and($this->fgaAllows('folder:x#viewer@user:nobody'))->toBeFalse()
        ->and($this->fgaAllows('group:a#member@user:zoe'))->toBeTrue();
});

it('refuses past the depth bound rather than guessing', function (): void {
    config(['cbox-id.fga.max_depth' => 5]);
    $this->fgaSchema(FGA_FOLDERS);

    $tuples = ['group:g0#member@user:deep'];

    foreach (range(1, 8) as $level) {
        $tuples[] = 'group:g'.$level.'#member@group:g'.($level - 1).'#member';
    }

    $this->fgaWrite(...$tuples);

    expect($this->fgaAllows('group:g3#member@user:deep'))->toBeTrue()
        ->and(fn () => $this->fgaAllows('group:g8#member@user:deep'))->toThrow(ResolutionTooComplex::class);
});

it('lists the resources a subject reaches and the subjects that reach a resource', function (): void {
    fgaFolders();
    $this->fgaWrite('document:faq#parent@folder:handbook', 'document:leave#blocked@user:alice');

    $fga = app(FineGrainedAuthorization::class);

    expect($this->fgaResources('user:olivia', 'viewer', 'document'))->toBe(['faq', 'leave'])
        ->and($this->fgaResources('user:alice', 'viewer', 'document'))->toBe(['leave'])
        ->and($this->fgaResources('user:alice', 'viewer', 'folder'))->toBe(['policies'])
        ->and($this->fgaResources('group:eng#member', 'viewer', 'document'))->toBe(['leave'])
        // Exclusion: candidates are confirmed one by one.
        ->and($this->fgaResources('user:alice', 'can_read', 'document'))->toBe([])
        ->and($this->fgaResources('user:olivia', 'can_read', 'document'))->toBe(['faq', 'leave'])
        ->and($fga->listSubjects(ResourceRef::of('document', 'leave'), 'viewer', 'user')->ids)->toBe(['alice', 'bob', 'olivia'])
        ->and($fga->listSubjects(ResourceRef::of('document', 'leave'), 'can_read', 'user')->ids)->toBe(['bob', 'olivia'])
        ->and($fga->listSubjects(ResourceRef::of('document', 'leave'), 'viewer', 'group')->ids)->toBe([]);

    // Pages, by cursor.
    $first = $fga->listSubjects(ResourceRef::of('document', 'leave'), 'viewer', 'user', limit: 2);
    $second = $fga->listSubjects(ResourceRef::of('document', 'leave'), 'viewer', 'user', limit: 2, after: $first->nextCursor);

    expect($first->ids)->toBe(['alice', 'bob'])
        ->and($first->nextCursor)->toBe('bob')
        ->and($second->ids)->toBe(['olivia'])
        ->and($second->hasMore())->toBeFalse();
});

it('answers a batch in order, at one revision', function (): void {
    fgaFolders();

    $results = app(FineGrainedAuthorization::class)->checkMany([
        Check::of('document', 'leave', 'viewer', SubjectRef::of('user', 'alice')),
        Check::of('document', 'leave', 'owner', SubjectRef::of('user', 'alice')),
        Check::of('folder', 'handbook', 'editor', SubjectRef::of('user', 'olivia')),
    ]);

    expect(array_map(static fn ($result): bool => $result->allowed, $results))->toBe([true, false, true])
        ->and((string) $results[0]->consistency)->toBe((string) $results[2]->consistency);
});

it('refuses tuples the schema does not allow, and writes nothing from a refused batch', function (): void {
    $this->fgaSchema(FGA_FOLDERS);

    $refusals = [
        'document:a#viewer@team:x' => 'does not take `team`',
        'document:a#viewer@group:eng' => 'does not take `group` — it takes [user, group#member]',
        'document:a#can_read@user:x' => 'is computed from other relations',
        'document:a#reader@user:x' => 'has no relation `reader`',
        'report:a#viewer@user:x' => 'defines no type `report`',
        'document:*#viewer@user:x' => 'is not a valid id',
    ];

    foreach ($refusals as $tuple => $message) {
        expect(fn () => $this->fgaWrite('document:ok#viewer@user:x', $tuple))
            ->toThrow(InvalidTuple::class, $message);
    }

    expect(FgaTuple::query()->count())->toBe(0)
        ->and(fn () => $this->fga()->writeTuples([Tuple::parse('document:a#viewer@user:x')], [Tuple::parse('document:a#viewer@user:x')]))
        ->toThrow(InvalidTuple::class, 'both written and deleted');
});

it('needs a schema before any tuple or check', function (): void {
    expect(fn () => $this->fgaWrite('document:a#viewer@user:x'))->toThrow(SchemaNotDefined::class)
        ->and(fn () => $this->fgaAllows('document:a#viewer@user:x'))->toThrow(SchemaNotDefined::class)
        ->and($this->fga()->schema()->defined())->toBeFalse();
});

it('refuses a check against a type or relation the schema does not define', function (): void {
    fgaFolders();

    expect(fn () => $this->fgaAllows('document:leave#reader@user:alice'))->toThrow(UnknownRelation::class, 'no relation `reader`')
        ->and(fn () => $this->fgaAllows('report:x#viewer@user:alice'))->toThrow(UnknownRelation::class)
        ->and(fn () => $this->fgaAllows('document:leave#viewer@robot:r2'))->toThrow(UnknownRelation::class)
        ->and(fn () => $this->fgaAllows('document:leave#viewer@group:eng#owner'))->toThrow(UnknownRelation::class);
});

it('treats re-writing and deleting nothing as no change, without a new revision', function (): void {
    fgaFolders();
    $before = $this->fga()->revision();

    $again = $this->fgaWrite('document:leave#editor@user:bob');
    $nothing = $this->fgaDelete('document:leave#editor@user:nobody');

    expect($again->written)->toBe(0)
        ->and($nothing->deleted)->toBe(0)
        ->and((string) $again->consistency)->toBe((string) $before)
        ->and((string) $this->fga()->revision())->toBe((string) $before);
});

it('refuses a schema change that would strand tuples, and accepts it once they are gone', function (): void {
    fgaFolders();

    $narrower = str_replace('relation editor: [user, group#member] or owner or editor from parent', 'relation editor: [user] or owner or editor from parent', FGA_FOLDERS);
    $withoutBlocked = str_replace(["  relation blocked: [user]\n", "  relation can_read: viewer but not blocked\n", '  relation can_share: owner and can_read'], ['', '', ''], FGA_FOLDERS);

    // Nothing is stranded by narrowing a relation no tuple uses the dropped form of.
    expect($this->fga()->updateSchema($narrower)->version)->toBe(2);

    $this->fgaWrite('document:leave#blocked@user:alice');

    try {
        $this->fga()->updateSchema($withoutBlocked);
        $this->fail('The change should have been refused.');
    } catch (SchemaConflict $conflict) {
        expect($conflict->stranded)->toBe([['resource_type' => 'document', 'relation' => 'blocked', 'subject' => 'user', 'tuples' => 1]]);
    }

    $this->fgaDelete('document:leave#blocked@user:alice');

    expect($this->fga()->updateSchema($withoutBlocked)->version)->toBe(3)
        ->and(fn () => $this->fga()->updateSchema("type user\ntype doc\n  relation x: [usr]"))->toThrow(InvalidSchema::class);
});

it('keeps one environment\'s schema, tuples, revisions and cache out of every other', function (): void {
    fgaFolders();
    $tokenA = $this->fga()->revision();

    // Same resource ids, same subject ids — another environment's model.
    $this->actingAsEnvironment('env_other');

    expect(fn () => $this->fgaAllows('document:leave#viewer@user:alice'))->toThrow(SchemaNotDefined::class);

    $this->fgaSchema(FGA_FOLDERS);

    expect($this->fgaAllows('document:leave#viewer@user:alice'))->toBeFalse()
        ->and($this->fgaResources('user:olivia', 'viewer', 'document'))->toBe([])
        ->and($this->fga()->tuples(new TupleFilter)->tuples)->toBe([])
        // A token minted by env_fga is refused here, not compared against this counter.
        ->and(fn () => $this->fgaAllows('document:leave#viewer@user:alice', (string) $tokenA))
        ->toThrow(InvalidConsistencyToken::class, 'another environment');

    $this->fgaWrite('document:leave#viewer@user:mallory');

    $this->actingAsEnvironment('env_fga');

    expect($this->fgaAllows('document:leave#viewer@user:alice'))->toBeTrue()
        ->and($this->fgaAllows('document:leave#viewer@user:mallory'))->toBeFalse()
        ->and(FgaStore::query()->count())->toBe(1);
});

it('honours a consistency token, and refuses a malformed one or one from the future', function (): void {
    fgaFolders();
    $written = $this->fgaWrite('document:leave#viewer@user:dana');

    expect($this->fgaAllows('document:leave#viewer@user:dana', (string) $written->consistency))->toBeTrue()
        ->and($written->consistency->revision)->toBe($this->fga()->revision()->revision)
        ->and(fn () => $this->fgaAllows('document:leave#viewer@user:dana', 'nonsense'))->toThrow(InvalidConsistencyToken::class, 'malformed')
        ->and(fn () => $this->fgaAllows('document:leave#viewer@user:dana', (string) ConsistencyToken::for('env_fga', 999)))
        ->toThrow(InvalidConsistencyToken::class, 'has not reached');
});

it('serves checks from the cache until a write advances the revision', function (): void {
    fgaFolders();

    expect($this->fgaAllows('document:leave#viewer@user:alice'))->toBeTrue();

    // Behind the cache's back: the cached answer still stands at this revision.
    DB::table('fga_tuples')->where('subject_id', 'alice')->delete();

    expect($this->fgaAllows('document:leave#viewer@user:alice'))->toBeTrue();

    // Any write advances the revision, and the next read asks a fresh key.
    $this->fgaWrite('document:other#viewer@user:someone');

    expect($this->fgaAllows('document:leave#viewer@user:alice'))->toBeFalse();
});

it('never serves an answer cached inside a transaction that rolled back', function (): void {
    fgaFolders();

    try {
        DB::transaction(function (): void {
            $this->fgaWrite('document:leave#viewer@user:ghost');

            // Cached under the uncommitted revision…
            expect($this->fgaAllows('document:leave#viewer@user:ghost'))->toBeTrue();

            throw new RuntimeException('roll back');
        });
    } catch (RuntimeException) {
    }

    // …and a different write commits the same revision NUMBER — with a different tag.
    $this->fgaWrite('document:leave#viewer@user:someone-else');

    expect($this->fgaAllows('document:leave#viewer@user:ghost'))->toBeFalse();
});

it('lists stored tuples with filters, by page', function (): void {
    fgaFolders();

    $all = $this->fga()->tuples(new TupleFilter, limit: 5);
    $rest = $this->fga()->tuples(new TupleFilter, limit: 5, after: $all->nextCursor);
    $usersets = $this->fga()->tuples(new TupleFilter(subjectRelation: 'member'));

    expect($all->tuples)->toHaveCount(5)
        ->and($rest->tuples)->toHaveCount(3)
        ->and($rest->nextCursor)->toBeNull()
        ->and(array_map(strval(...), $usersets->tuples))->toBe([
            'group:staff#member@group:eng#member',
            'folder:policies#viewer@group:staff#member',
        ])
        ->and(array_map(strval(...), $this->fga()->tuples(new TupleFilter(resourceType: 'document', resourceId: 'leave'))->tuples))
        ->toBe(['document:leave#parent@folder:policies', 'document:leave#editor@user:bob']);
});

it('answers a check over a complete digraph of groups in a bounded number of reads', function (): void {
    $this->fgaSchema("type user\n\ntype group\n  relation member: [user, group#member]\n");

    $tuples = [];

    foreach (range(0, 11) as $i) {
        foreach (range(0, 11) as $j) {
            if ($i !== $j) {
                $tuples[] = "group:g{$i}#member@group:g{$j}#member";
            }
        }
    }

    // A member nested several levels deep, through a chain that loops back on itself.
    foreach (range(0, 4) as $level) {
        $tuples[] = 'group:c'.$level.'#member@group:c'.($level + 1).'#member';
    }

    $tuples[] = 'group:c5#member@group:c0#member';
    $tuples[] = 'group:c5#member@user:carol';
    $tuples[] = 'group:g11#member@group:c3#member';

    foreach (array_chunk($tuples, 100) as $batch) {
        $this->fgaWrite(...$batch);
    }

    $reads = 0;
    DB::listen(static function ($query) use (&$reads): void {
        if (str_contains($query->sql, 'fga_tuples')) {
            $reads++;
        }
    });

    $started = microtime(true);
    $results = $this->fga()->checkMany([
        Check::of('group', 'g0', 'member', SubjectRef::of('user', 'fresh1')),
        Check::of('group', 'g0', 'member', SubjectRef::of('user', 'fresh2')),
    ]);

    expect(array_map(static fn ($result): bool => $result->allowed, $results))->toBe([false, false])
        // Every node expanded at most once per subject: 12 groups plus the c chain it reaches.
        ->and($reads)->toBeLessThanOrEqual(2 * 20)
        ->and(microtime(true) - $started)->toBeLessThan(2.0)
        ->and($this->fgaAllows('group:g0#member@user:carol'))->toBeTrue()
        ->and($this->fgaAllows('group:c0#member@user:carol'))->toBeTrue()
        ->and($this->fgaAllows('group:c3#member@user:carol'))->toBeTrue()
        ->and($this->fgaAllows('group:g5#member@user:mallory'))->toBeFalse();
});

it('refuses a check batch past the expansion budget rather than searching on', function (): void {
    config(['cbox-id.fga.max_expansion' => 10]);
    $this->fgaSchema("type user\n\ntype group\n  relation member: [user, group#member]\n");

    $tuples = [];

    foreach (range(0, 5) as $i) {
        foreach (range(0, 5) as $j) {
            if ($i !== $j) {
                $tuples[] = "group:g{$i}#member@group:g{$j}#member";
            }
        }
    }

    $this->fgaWrite(...$tuples);

    // Six expansions per fresh subject: the budget is shared across the batch.
    expect($this->fgaAllows('group:g0#member@user:one'))->toBeFalse()
        ->and(fn () => $this->fga()->checkMany([
            Check::of('group', 'g0', 'member', SubjectRef::of('user', 'two')),
            Check::of('group', 'g0', 'member', SubjectRef::of('user', 'three')),
        ]))->toThrow(ResolutionTooComplex::class);
});

it('keys the answer cache unambiguously, so one question never answers another', function (): void {
    fgaFolders();
    $this->fgaWrite('document:z9#viewer@user:bob', 'document:d1#viewer@user:bob|7|x');

    $fga = app(FineGrainedAuthorization::class);

    // `bob` with limit 7 after `x|100|` used to render the same question as `bob|7|x`.
    expect($fga->listResources(SubjectRef::of('user', 'bob'), 'viewer', 'document', limit: 7, after: 'x|100|')->ids)->toBe(['z9'])
        ->and($fga->listResources(SubjectRef::of('user', 'bob|7|x'), 'viewer', 'document', limit: 100, after: '')->ids)->toBe(['d1'])
        ->and($fga->listSubjects(ResourceRef::of('document', 'z9'), 'viewer', 'user', limit: 1, after: 'a|2|')->ids)->toBe(['bob'])
        ->and($fga->listSubjects(ResourceRef::of('document', 'd1'), 'viewer', 'user', limit: 100)->ids)->toBe(['bob|7|x']);
});

it('refuses an id that could never be stored, instead of answering under another question\'s key', function (): void {
    fgaFolders();

    // A plain subject id `eng#member` rendered exactly like the userset group:eng#member.
    expect(fn () => $this->fga()->check(Check::of('document', 'leave', 'viewer', SubjectRef::of('group', 'eng#member'))))
        ->toThrow(InvalidTuple::class, 'not a valid id')
        ->and($this->fgaAllows('document:leave#viewer@group:eng#member'))->toBeTrue()
        ->and(fn () => $this->fga()->check(Check::of('document', 'le@ve', 'viewer', SubjectRef::of('user', 'alice'))))
        ->toThrow(InvalidTuple::class, 'not a valid id')
        ->and(fn () => $this->fga()->listResources(SubjectRef::of('user', 'a b'), 'viewer', 'document'))
        ->toThrow(InvalidTuple::class, 'not a valid id')
        ->and(fn () => $this->fga()->listSubjects(ResourceRef::of('document', 'x#y'), 'viewer', 'user'))
        ->toThrow(InvalidTuple::class, 'not a valid id')
        ->and(fn () => $this->fga()->listSubjects(ResourceRef::of('document', 'leave'), 'viewer', 'user', after: "bob\n"))
        ->toThrow(InvalidTuple::class, 'cursor');
});
