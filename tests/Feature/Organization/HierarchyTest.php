<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
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
