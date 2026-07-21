<?php

declare(strict_types=1);

use Cbox\Id\Directory\Support\ScimUserFilter;

it('parses each supported operator into a clause', function (string $filter, string $column, string $operator, ?string $value): void {
    $parsed = ScimUserFilter::parse($filter);

    expect($parsed)->not->toBeNull();
    expect($parsed->clauses)->toHaveCount(1);

    $clause = $parsed->clauses[0];
    expect($clause->column)->toBe($column)
        ->and($clause->operator)->toBe($operator)
        ->and($clause->value)->toBe($value);
})->with([
    'eq' => ['userName eq "sam"', 'resource->userName', 'eq', 'sam'],
    'ne' => ['userName ne "sam"', 'resource->userName', 'ne', 'sam'],
    'co' => ['userName co "sa"', 'resource->userName', 'co', 'sa'],
    'sw' => ['userName sw "sa"', 'resource->userName', 'sw', 'sa'],
    'ew' => ['userName ew "am"', 'resource->userName', 'ew', 'am'],
    'pr' => ['userName pr', 'resource->userName', 'pr', null],
    'externalId' => ['externalId eq "x1"', 'external_id', 'eq', 'x1'],
    'boolean' => ['active eq true', 'active', 'eq', 'true'],
]);

it('parses a compound filter with a single top-level and/or', function (): void {
    $and = ScimUserFilter::parse('userName eq "sam" and active eq true');
    expect($and)->not->toBeNull()
        ->and($and->clauses)->toHaveCount(2)
        ->and($and->conjunction)->toBe('and');

    $or = ScimUserFilter::parse('userName eq "a" or userName eq "b"');
    expect($or)->not->toBeNull()->and($or->conjunction)->toBe('or');
});

it('rejects unsupported operators, grouping and mixed conjunctions', function (string $filter): void {
    expect(ScimUserFilter::parse($filter))->toBeNull();
})->with([
    'gt' => 'userName gt "a"',
    'ge' => 'userName ge "a"',
    'lt' => 'userName lt "a"',
    'le' => 'userName le "a"',
    'not' => 'not (userName eq "a")',
    'grouping' => '(userName eq "a")',
    'mixed and/or' => 'userName eq "a" and userName eq "b" or active eq true',
    'unknown attribute' => 'nickName eq "x"',
    'garbage' => 'garbage',
    'incomplete' => 'userName eq',
]);
