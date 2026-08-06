<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Subject;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('grants and checks a direct relationship', function (): void {
    $store = app(RelationshipStore::class);
    $store->write(new Relationship('org', 'doc', '1', 'viewer', 'user', 'alice'));

    expect($store->check('org', 'doc', '1', 'viewer', 'user', 'alice'))->toBeTrue();
});

it('denies by default when there is no grant', function (): void {
    $store = app(RelationshipStore::class);
    $store->write(new Relationship('org', 'doc', '1', 'viewer', 'user', 'alice'));

    expect($store->check('org', 'doc', '1', 'viewer', 'user', 'bob'))->toBeFalse()
        ->and($store->check('org', 'doc', '1', 'editor', 'user', 'alice'))->toBeFalse()
        ->and($store->check('other-org', 'doc', '1', 'viewer', 'user', 'alice'))->toBeFalse();
});

it('revokes a relationship on delete', function (): void {
    $store = app(RelationshipStore::class);
    $rel = new Relationship('org', 'doc', '1', 'viewer', 'user', 'alice');
    $store->write($rel);
    expect($store->check('org', 'doc', '1', 'viewer', 'user', 'alice'))->toBeTrue();

    $store->delete($rel);
    expect($store->check('org', 'doc', '1', 'viewer', 'user', 'alice'))->toBeFalse();
});

it('resolves membership through a userset (group)', function (): void {
    $store = app(RelationshipStore::class);
    $store->write(new Relationship('org', 'group', 'eng', 'member', 'user', 'alice'));
    $store->write(new Relationship('org', 'doc', '1', 'viewer', 'group', 'eng', 'member'));

    expect($store->check('org', 'doc', '1', 'viewer', 'user', 'alice'))->toBeTrue()
        ->and($store->check('org', 'doc', '1', 'viewer', 'user', 'bob'))->toBeFalse();
});

it('resolves transitively through nested usersets', function (): void {
    $store = app(RelationshipStore::class);
    $store->write(new Relationship('org', 'team', 'core', 'member', 'user', 'alice'));
    $store->write(new Relationship('org', 'group', 'eng', 'member', 'team', 'core', 'member'));
    $store->write(new Relationship('org', 'doc', '1', 'viewer', 'group', 'eng', 'member'));

    expect($store->check('org', 'doc', '1', 'viewer', 'user', 'alice'))->toBeTrue();
});

it('terminates and denies on a cyclic userset', function (): void {
    $store = app(RelationshipStore::class);
    $store->write(new Relationship('org', 'group', 'a', 'member', 'group', 'b', 'member'));
    $store->write(new Relationship('org', 'group', 'b', 'member', 'group', 'a', 'member'));

    expect($store->check('org', 'group', 'a', 'member', 'user', 'nobody'))->toBeFalse();
});

it('exposes decisions and entitlements through the PDP', function (): void {
    $this->relate(new Relationship('org', 'document', '42', 'editor', 'user', 'alice'));
    $this->grantEntitlement('org', 'feature.sso');

    $pdp = app(PolicyDecisionPoint::class);

    expect($pdp->can('org', Subject::user('alice'), 'editor', ResourceRef::of('document', '42')))->toBeTrue()
        ->and($pdp->decide('org', Subject::user('bob'), 'editor', ResourceRef::of('document', '42'))->allowed)->toBeFalse()
        ->and($pdp->entitlement('org', 'feature.sso'))->not->toBeNull();
});

it('resolves a dense cyclic userset graph without combinatorial blowup', function (): void {
    $store = app(RelationshipStore::class);

    // 10 groups, each a member-userset of every other — a dense cycle that,
    // without a visited set, would fan out to ~10^depth paths.
    foreach (range(0, 9) as $i) {
        foreach (range(0, 9) as $j) {
            if ($i !== $j) {
                $store->write(new Relationship('org', 'group', "g{$i}", 'member', 'group', "g{$j}", 'member'));
            }
        }
    }

    // Nobody is a member — must deny, and must return quickly (guards the fix).
    expect($store->check('org', 'group', 'g0', 'member', 'user', 'nobody'))->toBeFalse();

    // Add alice to one group; g0 reaches her through the graph.
    $store->write(new Relationship('org', 'group', 'g9', 'member', 'user', 'alice'));
    expect($store->check('org', 'group', 'g0', 'member', 'user', 'alice'))->toBeTrue();
});
