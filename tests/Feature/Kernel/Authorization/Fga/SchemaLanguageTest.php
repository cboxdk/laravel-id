<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidSchema;
use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use Cbox\Id\Kernel\Authorization\Schema\ButNot;
use Cbox\Id\Kernel\Authorization\Schema\SchemaError;
use Cbox\Id\Kernel\Authorization\Schema\SchemaParser;
use Cbox\Id\Kernel\Authorization\Schema\UnionOf;

/*
| The schema language: what parses, what it means, and every way it is refused — each
| refusal by line, all of them at once.
*/

const SCHEMA_DOCS = <<<'SCHEMA'
    # Documents live in folders; a folder's viewers can read everything in it.
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
      relation can_share: owner and (viewer but not blocked)
    SCHEMA;

/**
 * @return list<string>
 */
function schemaErrors(string $source): array
{
    try {
        (new SchemaParser)->parse($source);
    } catch (InvalidSchema $invalid) {
        return array_map(static fn (SchemaError $error): string => (string) $error, $invalid->errors);
    }

    return [];
}

it('parses the folders-and-documents model', function (): void {
    $schema = (new SchemaParser)->parse(SCHEMA_DOCS);

    expect(array_keys($schema->types))->toBe(['user', 'group', 'folder', 'document'])
        ->and($schema->relation('folder', 'viewer')?->rewrite)->toBeInstanceOf(UnionOf::class)
        ->and($schema->relation('document', 'can_read')?->rewrite)->toBeInstanceOf(ButNot::class)
        ->and($schema->relation('folder', 'viewer')?->directlyRelated()?->allows('group', 'member'))->toBeTrue()
        ->and($schema->relation('folder', 'viewer')?->directlyRelated()?->allows('group', null))->toBeFalse()
        ->and($schema->relation('document', 'can_read')?->directlyRelated())->toBeNull()
        ->and($schema->isUnionOnly('folder', 'viewer'))->toBeTrue()
        ->and($schema->isUnionOnly('document', 'can_share'))->toBeFalse();
});

it('round-trips through its JSON form and its canonical text', function (): void {
    $schema = (new SchemaParser)->parse(SCHEMA_DOCS);

    $reloaded = AuthorizationSchema::fromArray(json_decode((string) json_encode($schema->toArray()), true));
    $reparsed = (new SchemaParser)->parse($schema->toDsl());

    expect($reloaded->toArray())->toBe($schema->toArray())
        ->and($reparsed->toArray())->toBe($schema->toArray())
        ->and($schema->toDsl())->toContain('  relation can_share: owner and (viewer but not blocked)')
        ->and($schema->toArray()['types'][2]['relations'][3]['rewrite'])->toBe(['union' => [
            ['direct' => [['type' => 'user'], ['type' => 'group', 'relation' => 'member']]],
            ['computed' => 'editor'],
            ['from' => ['tupleset' => 'parent', 'relation' => 'viewer']],
        ]]);
});

it('keeps `group#member` while stripping comments', function (): void {
    $schema = (new SchemaParser)->parse("type user # people\n# a whole-line comment\ntype group\n  relation member: [user, group#member] # nested groups\n");

    expect($schema->relation('group', 'member')?->directlyRelated()?->allows('group', 'member'))->toBeTrue();
});

it('refuses names it does not define, by line, all at once', function (): void {
    expect(schemaErrors(<<<'SCHEMA'
        type user
        type doc
          relation viewer: [usr]
          relation editor: [user] or ownr
          relation reader: [team#member]
          relation lister: [user#friend]
        SCHEMA))->toBe([
        'Line 3: `viewer` on `doc` names the type `usr`, which is not defined.',
        'Line 4: `editor` on `doc` refers to `ownr`, which `doc` does not define.',
        'Line 5: `reader` on `doc` names the type `team`, which is not defined.',
        'Line 6: `lister` on `doc` names `user#friend`, but `user` has no relation `friend`.',
    ]);
});

it('refuses tuple-to-userset through anything but a plain list of types', function (): void {
    expect(schemaErrors(<<<'SCHEMA'
        type user
        type group
          relation member: [user]
        type folder
          relation viewer: [user]
        type doc
          relation parent: [folder]
          relation owners: [group#member]
          relation computed: parent
          relation a: viewer from nothing
          relation b: viewer from owners
          relation c: viewer from computed
          relation d: editor from parent
        SCHEMA))->toBe([
        'Line 10: `a` on `doc` inherits from `nothing`, which `doc` does not define.',
        'Line 11: `b` on `doc` inherits through `owners`, which lists the userset `group#member`; a relation you inherit through may only list types like `[folder]`.',
        'Line 12: `c` on `doc` inherits through `computed`, which must be a plain list of types like `[folder]` — not computed from other relations.',
        'Line 13: `d` on `doc` inherits `editor` from `parent`, but no type `parent` points at defines `editor`.',
    ]);
});

it('refuses an exclusion that refers back to the relation it decides', function (): void {
    expect(schemaErrors(<<<'SCHEMA'
        type user
        type doc
          relation viewer: [user] but not banned
          relation banned: [user] or viewer
        SCHEMA))->toBe([
        'Line 3: `viewer` on `doc` subtracts `doc#banned`, which depends on `doc#viewer` itself — an exclusion cannot refer back to the relation it decides.',
    ]);

    // Through a tupleset, too: a folder's viewers minus the folder's own viewers.
    expect(schemaErrors(<<<'SCHEMA'
        type user
        type folder
          relation parent: [folder]
          relation viewer: [user] but not viewer from parent
        SCHEMA))->toHaveCount(1);
});

it('allows cycles that only add access — nested groups, folder trees', function (): void {
    expect(schemaErrors(<<<'SCHEMA'
        type user
        type group
          relation member: [user, group#member]
        type folder
          relation parent: [folder]
          relation viewer: [user, group#member] or viewer from parent
        SCHEMA))->toBe([]);
});

it('refuses syntax it cannot read, and says what it expected', function (): void {
    expect(schemaErrors(<<<'SCHEMA'
        relation orphan: [user]
        type user
        type doc
          relation a: [user] or b and c
          relation b: [user
          relation c: (b
          relation d:
          relation e: [user] but not b but not c
          relation f: [user] b
          define g: [user]
          relation h: [user]
          relation h: [user]
          relation self: self
          relation 2bad: [user]
          relation i: [user, user]
          relation j: [user] or [user]
        type doc
        SCHEMA))->toBe([
        'Line 1: A relation must follow the `type` it belongs to.',
        'Line 4: `or` and `and` cannot be mixed without parentheses.',
        'Line 5: A list of types is written `[user, group#member]`.',
        'Line 6: Expected `)` before the end of the line.',
        'Line 7: The relation has no definition.',
        'Line 8: Only one `but not` per expression — use parentheses for more.',
        'Line 9: Unexpected `b`.',
        'Line 10: Expected `type name` or `relation name: definition`.',
        'Line 12: `h` is defined twice on `doc`.',
        'Line 13: `self` on `doc` is defined as itself.',
        'Line 14: `2bad` is not a valid relation name: use lower-case letters, digits, `_` and `-`, starting with a letter.',
        'Line 15: `i` on `doc` lists `user` twice.',
        'Line 16: `j` on `doc` has more than one `[...]` list — merge them into one.',
        'Line 17: `doc` is defined twice.',
    ]);
});

it('refuses an empty schema and an oversized one', function (): void {
    expect(schemaErrors("# nothing\n"))->toBe(['The schema defines no types.'])
        ->and(schemaErrors(str_repeat('a', SchemaParser::MAX_LENGTH + 1)))->toHaveCount(1);
});
