<?php

declare(strict_types=1);

use Cbox\Id\Directory\Support\ScimUserFilter;

it('parses each supported operator into a clause', function (string $filter, string $column, string $operator, string|bool|null $value): void {
    $parsed = ScimUserFilter::parse($filter);

    expect($parsed)->not->toBeNull();
    expect($parsed->clauses)->toHaveCount(1);

    $clause = $parsed->clauses[0];
    expect($clause->column)->toBe($column)
        ->and($clause->operator)->toBe($operator)
        ->and($clause->value)->toBe($value);
})->with([
    // userName and emails resolve to their pre-folded comparison columns, not the
    // JSON blob — matching inside the blob inherited the database's collation.
    'eq' => ['userName eq "sam"', 'user_name_lower', 'eq', 'sam'],
    'ne' => ['userName ne "sam"', 'user_name_lower', 'ne', 'sam'],
    'co' => ['userName co "sa"', 'user_name_lower', 'co', 'sa'],
    'sw' => ['userName sw "sa"', 'user_name_lower', 'sw', 'sa'],
    'ew' => ['userName ew "am"', 'user_name_lower', 'ew', 'am'],
    'pr' => ['userName pr', 'user_name_lower', 'pr', null],
    'externalId' => ['externalId eq "x1"', 'external_id', 'eq', 'x1'],
    'emails' => ['emails.value eq "sam@corp.com"', 'email_lower', 'eq', 'sam@corp.com'],
    // The literal is coerced to the type the column stores, at parse time.
    'boolean' => ['active eq true', 'active', 'eq', true],
    'boolean string' => ['active eq "false"', 'active', 'eq', false],
]);

it('folds a case-insensitive attribute to its comparison form', function (): void {
    // RFC 7643 marks userName caseExact:false and DiscoveryController advertises it as
    // uniqueness:"server". A case-SENSITIVE predicate meant an IdP's pre-provision check
    // for "Dana.Rivera" missed the stored "dana.rivera" — and minted a second account.
    $parsed = ScimUserFilter::parse('userName eq "Dana.Rivera@corp.com"');

    expect($parsed?->clauses[0]->value)->toBe('dana.rivera@corp.com');
});

it('parses the meta.lastModified watermark a delta sync is built on', function (): void {
    $parsed = ScimUserFilter::parse('meta.lastModified gt "2026-07-01T00:00:00Z"');

    expect($parsed)->not->toBeNull()
        ->and($parsed->clauses[0]->column)->toBe('updated_at')
        ->and($parsed->clauses[0]->operator)->toBe('gt')
        // Normalized to UTC in the shape Eloquent stores timestamps in.
        ->and($parsed->clauses[0]->value)->toBe('2026-07-01 00:00:00');
});

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
    // Ordering comparisons are implemented for timestamps only; on text they would be
    // answered with whatever the collation happened to order, so they stay refused.
    'gt' => 'userName gt "a"',
    'ge' => 'userName ge "a"',
    'lt' => 'userName lt "a"',
    'le' => 'userName le "a"',
    // Substring matching against a boolean column is meaningless, not "no results".
    'co on a boolean' => 'active co "tru"',
    'not' => 'not (userName eq "a")',
    'grouping' => '(userName eq "a")',
    'mixed and/or' => 'userName eq "a" and userName eq "b" or active eq true',
    'unknown attribute' => 'nickName eq "x"',
    'garbage' => 'garbage',
    'incomplete' => 'userName eq',
]);

/**
 * A literal that cannot be a value of the attribute's type at all must refuse the
 * WHOLE filter. `active eq "fasle"` used to be coerced to `active = false` and answered
 * with every deactivated user — a confidently wrong result set, reported as a success.
 */
it('refuses a literal that is not a value of the attribute type', function (string $filter): void {
    expect(ScimUserFilter::parse($filter))->toBeNull();
})->with([
    'misspelled boolean' => 'active eq "fasle"',
    'numeric boolean' => 'active eq "0"',
    'empty boolean' => 'active eq ""',
    'unparsable timestamp' => 'meta.lastModified gt "yesterday"',
    'empty timestamp' => 'meta.lastModified gt ""',
]);
