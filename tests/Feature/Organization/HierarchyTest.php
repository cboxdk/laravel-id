<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\Exceptions\CannotReparent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('records ancestors and descendants for a child', function (): void {
    $parent = $this->makeOrganization('Reseller');
    $child = $this->makeOrganization('Customer', parentId: $parent->id);

    $hierarchy = app(OrganizationHierarchy::class);

    expect($hierarchy->descendants($parent->id))->toBe([$child->id])
        ->and($hierarchy->ancestors($child->id))->toBe([$parent->id])
        ->and($hierarchy->isDescendantOf($child->id, $parent->id))->toBeTrue();
});

it('resolves the tree transitively at depth', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B', parentId: $a->id);
    $c = $this->makeOrganization('C', parentId: $b->id);

    $hierarchy = app(OrganizationHierarchy::class);

    expect($hierarchy->descendants($a->id))->toContain($b->id, $c->id)
        ->and($hierarchy->ancestors($c->id))->toContain($a->id, $b->id)
        ->and($hierarchy->isDescendantOf($c->id, $a->id))->toBeTrue();
});

it('answers transitive management queries for resellers', function (): void {
    $reseller = $this->makeOrganization('R');
    $customer = $this->makeOrganization('Cu', parentId: $reseller->id);
    $unrelated = $this->makeOrganization('O');

    $hierarchy = app(OrganizationHierarchy::class);

    expect($hierarchy->manages($reseller->id, $customer->id))->toBeTrue()
        ->and($hierarchy->manages($reseller->id, $reseller->id))->toBeTrue()
        ->and($hierarchy->manages($customer->id, $reseller->id))->toBeFalse()
        ->and($hierarchy->manages($unrelated->id, $customer->id))->toBeFalse();
});

it('moves a node with its whole subtree under a new parent', function (): void {
    $hierarchy = app(OrganizationHierarchy::class);

    // a -> b -> c, and a separate root d.
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B', parentId: $a->id);
    $c = $this->makeOrganization('C', parentId: $b->id);
    $d = $this->makeOrganization('D');

    // Move b (carrying c) under d.
    $hierarchy->move($b->id, $d->id);

    // b and c now sit under d, no longer under a.
    expect($hierarchy->ancestors($b->id))->toBe([$d->id])
        ->and($hierarchy->ancestors($c->id))->toContain($d->id, $b->id)
        ->and($hierarchy->ancestors($c->id))->not->toContain($a->id)
        ->and($hierarchy->descendants($a->id))->toBe([])
        ->and($hierarchy->descendants($d->id))->toContain($b->id, $c->id)
        ->and($hierarchy->isDescendantOf($c->id, $d->id))->toBeTrue();
});

it('promotes a node to a root when moved with a null parent', function (): void {
    $hierarchy = app(OrganizationHierarchy::class);
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B', parentId: $a->id);

    $hierarchy->move($b->id, null);

    expect($hierarchy->ancestors($b->id))->toBe([])
        ->and($hierarchy->descendants($a->id))->toBe([]);
});

it('refuses to move a node under its own descendant', function (): void {
    $hierarchy = app(OrganizationHierarchy::class);
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B', parentId: $a->id);

    $hierarchy->move($a->id, $b->id);
})->throws(CannotReparent::class);
