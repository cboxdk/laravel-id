<?php

declare(strict_types=1);

use Cbox\Id\Scim\Enums\ScimComparisonOperator;
use Cbox\Id\Scim\Enums\ScimLogicalOperator;
use Cbox\Id\Scim\Exceptions\InvalidScimFilter;
use Cbox\Id\Scim\Filter\Nodes\ComparisonNode;
use Cbox\Id\Scim\Filter\Nodes\LogicalNode;
use Cbox\Id\Scim\Filter\Nodes\NotNode;
use Cbox\Id\Scim\Filter\Nodes\PresentNode;
use Cbox\Id\Scim\Filter\Nodes\ValuePathNode;
use Cbox\Id\Scim\Filter\ScimFilterEvaluator;
use Cbox\Id\Scim\Filter\ScimFilterParser;

/**
 * The SCIM filter grammar (RFC 7644 §3.4.2.2, Figure 1) and PATCH path grammar
 * (§3.5.2). The canonical rendering is fully parenthesised, so every precedence test
 * below reads the tree the parser actually built.
 */
function scimFilter(string $filter): string
{
    return (new ScimFilterParser)->parse($filter)->toString();
}

it('parses every comparison operator, case-insensitively', function (string $operator, ScimComparisonOperator $expected): void {
    $node = (new ScimFilterParser)->parse('userName '.$operator.' "bjensen"');

    expect($node)->toBeInstanceOf(ComparisonNode::class)
        ->and($node->operator)->toBe($expected)
        ->and($node->value)->toBe('bjensen');
})->with([
    ['eq', ScimComparisonOperator::Equal],
    ['EQ', ScimComparisonOperator::Equal],
    ['Eq', ScimComparisonOperator::Equal],
    ['ne', ScimComparisonOperator::NotEqual],
    ['co', ScimComparisonOperator::Contains],
    ['sw', ScimComparisonOperator::StartsWith],
    ['ew', ScimComparisonOperator::EndsWith],
    ['gt', ScimComparisonOperator::GreaterThan],
    ['ge', ScimComparisonOperator::GreaterThanOrEqual],
    ['lt', ScimComparisonOperator::LessThan],
    ['LE', ScimComparisonOperator::LessThanOrEqual],
]);

it('parses the presence operator', function (): void {
    $node = (new ScimFilterParser)->parse('title PR');

    expect($node)->toBeInstanceOf(PresentNode::class)
        ->and($node->path->attribute)->toBe('title');
});

it('parses every JSON value a comparison can take', function (string $literal, mixed $expected): void {
    $node = (new ScimFilterParser)->parse('x eq '.$literal);

    expect($node)->toBeInstanceOf(ComparisonNode::class)
        ->and($node->value)->toBe($expected);
})->with([
    'true' => ['true', true],
    'false' => ['false', false],
    'null' => ['null', null],
    'True, folded' => ['True', true],
    'integer' => ['42', 42],
    'negative' => ['-7', -7],
    'decimal' => ['1.5', 1.5],
    'exponent' => ['1e3', 1000.0],
    'string' => ['"hello"', 'hello'],
    'date string' => ['"2011-05-13T04:42:34Z"', '2011-05-13T04:42:34Z'],
    'empty string' => ['""', ''],
]);

it('decodes JSON escapes in string literals', function (string $literal, string $expected): void {
    $node = (new ScimFilterParser)->parse('name.familyName co '.$literal);

    expect($node)->toBeInstanceOf(ComparisonNode::class)
        ->and($node->value)->toBe($expected);
})->with([
    'quote' => ['"say \"hi\""', 'say "hi"'],
    'backslash' => ['"a\\\\b"', 'a\\b'],
    'slash' => ['"a\/b"', 'a/b'],
    'unicode apostrophe' => ['"O\u0027Malley"', "O'Malley"],
    'surrogate pair' => ['"\ud83d\ude00"', "\u{1F600}"],
    'raw apostrophe' => ['"O\'Malley"', "O'Malley"],
    'newline' => ['"a\nb"', "a\nb"],
    'brackets inside a string' => ['"a [b] (c)"', 'a [b] (c)'],
    'keywords inside a string' => ['"x and y or not z"', 'x and y or not z'],
]);

it('gives not precedence over and, and and over or', function (string $filter, string $tree): void {
    expect(scimFilter($filter))->toBe($tree);
})->with([
    'and binds tighter than or' => [
        'a eq 1 or b eq 2 and c eq 3',
        '(a eq 1 or (b eq 2 and c eq 3))',
    ],
    'and binds tighter than or, either side' => [
        'a eq 1 and b eq 2 or c eq 3',
        '((a eq 1 and b eq 2) or c eq 3)',
    ],
    'not binds tighter than and' => [
        'not (a eq 1) and b eq 2',
        '(not (a eq 1) and b eq 2)',
    ],
    'chains are left-associative' => [
        'a eq 1 and b eq 2 and c eq 3',
        '((a eq 1 and b eq 2) and c eq 3)',
    ],
    'parentheses override precedence' => [
        '(a eq 1 or b eq 2) and c eq 3',
        '((a eq 1 or b eq 2) and c eq 3)',
    ],
    'nested parentheses' => [
        '((a eq 1))',
        'a eq 1',
    ],
    'the RFC example with not' => [
        'userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")',
        '(userType ne "Employee" and not ((emails co "example.com" or emails.value co "example.org")))',
    ],
    'keywords in any case' => [
        'a eq 1 AND b eq 2 Or NOT (c pr)',
        '((a eq 1 and b eq 2) or not (c pr))',
    ],
]);

it('parses value-path filters', function (): void {
    $node = (new ScimFilterParser)->parse('emails[type eq "work" and value co "@example.com"]');

    expect($node)->toBeInstanceOf(ValuePathNode::class)
        ->and($node->attribute->attribute)->toBe('emails')
        ->and($node->filter)->toBeInstanceOf(LogicalNode::class)
        ->and($node->toString())->toBe('emails[(type eq "work" and value co "@example.com")]');
});

it('combines value paths with logical operators, as in the RFC example', function (): void {
    expect(scimFilter('emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]'))
        ->toBe('(emails[(type eq "work" and value co "@example.com")] or ims[(type eq "xmpp" and value co "@foo.com")])');

    expect(scimFilter('userType eq "Employee" and emails[type eq "work" and value co "@example.com"]'))
        ->toBe('(userType eq "Employee" and emails[(type eq "work" and value co "@example.com")])');
});

it('reads the Entra uniqueness filter on the work email as a value filter', function (): void {
    // Not Figure 1, but documented by Microsoft Entra ID for user uniqueness keyed on
    // the work email — and it means exactly this value filter.
    expect(scimFilter('emails[type eq "work"].value eq "user@contoso.com"'))
        ->toBe('emails[(type eq "work" and value eq "user@contoso.com")]');
});

it('allows not and grouping inside a value filter', function (): void {
    expect(scimFilter('members[not (value eq "a") and (display co "x" or display co "y")]'))
        ->toBe('members[(not (value eq "a") and (display co "x" or display co "y"))]');
});

it('splits URN-qualified attribute paths at the last colon', function (): void {
    $core = (new ScimFilterParser)->parse('urn:ietf:params:scim:schemas:core:2.0:User:name.familyName sw "J"');

    expect($core)->toBeInstanceOf(ComparisonNode::class)
        ->and($core->path->schema)->toBe('urn:ietf:params:scim:schemas:core:2.0:User')
        ->and($core->path->attribute)->toBe('name')
        ->and($core->path->subAttribute)->toBe('familyName')
        ->and($core->path->canonical())->toBe('name.familyname');

    $extension = (new ScimFilterParser)->parse('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value eq "x"');

    expect($extension)->toBeInstanceOf(ComparisonNode::class)
        ->and($extension->path->inSchema('URN:IETF:PARAMS:SCIM:SCHEMAS:EXTENSION:ENTERPRISE:2.0:USER'))->toBeTrue()
        ->and($extension->path->canonical())->toBe('manager.value');
});

it('refuses malformed filters', function (string $filter): void {
    expect(fn () => (new ScimFilterParser)->parse($filter))->toThrow(InvalidScimFilter::class);
})->with([
    'empty' => [''],
    'whitespace' => ['   '],
    'no operator' => ['userName'],
    'no value' => ['userName eq'],
    'unknown operator' => ['userName regex "x"'],
    'unquoted word value' => ['externalId eq jyoung'],
    'unterminated string' => ['userName eq "abc'],
    'single quotes in a filter' => ["userName eq 'abc'"],
    'invalid escape' => ['userName eq "a\\qb"'],
    'lone surrogate' => ['userName eq "\\ud800"'],
    'raw control character' => ["userName eq \"a\tb\""],
    'unbalanced open paren' => ['(userName eq "a"'],
    'unbalanced close paren' => ['userName eq "a")'],
    'empty parens' => ['()'],
    'not without parens' => ['not userName eq "a"'],
    'dangling and' => ['userName eq "a" and'],
    'leading or' => ['or userName eq "a"'],
    'double operator' => ['userName eq eq "a"'],
    'two expressions without a joiner' => ['a eq 1 b eq 2'],
    'unclosed bracket' => ['emails[type eq "work"'],
    'nested brackets' => ['emails[type[value eq "x"] pr]'],
    'qualified path inside brackets' => ['emails[urn:x:type eq "work"]'],
    'dotted path inside brackets' => ['emails[type.value eq "work"]'],
    'bracket after a sub-attribute' => ['name.familyName[value eq "x"]'],
    'not a URN' => ['http://example.com:userName eq "x"'],
    'two sub-attributes' => ['a.b.c eq "x"'],
    'stray character' => ['userName eq "a" & userName eq "b"'],
    'bare value' => ['"abc"'],
]);

it('refuses a filter longer than the configured limit', function (): void {
    $parser = new ScimFilterParser(maxLength: 64);

    expect(fn () => $parser->parse('userName eq "'.str_repeat('a', 80).'"'))
        ->toThrow(InvalidScimFilter::class, 'longer than');
});

it('refuses nesting deeper than the configured limit', function (): void {
    $deep = str_repeat('(', 17).'a eq 1'.str_repeat(')', 17);

    expect(fn () => (new ScimFilterParser)->parse($deep))->toThrow(InvalidScimFilter::class, 'nests deeper');
    expect(scimFilter(str_repeat('(', 16).'a eq 1'.str_repeat(')', 16)))->toBe('a eq 1');

    // `not` and value-path brackets count as nesting too.
    $nots = str_repeat('not (', 17).'a eq 1'.str_repeat(')', 17);
    expect(fn () => (new ScimFilterParser)->parse($nots))->toThrow(InvalidScimFilter::class, 'nests deeper');
});

it('refuses more comparisons than the configured limit', function (): void {
    $wide = implode(' or ', array_fill(0, 65, 'a eq 1'));

    expect(fn () => (new ScimFilterParser)->parse($wide))->toThrow(InvalidScimFilter::class, 'more than the 64');
    expect(fn () => (new ScimFilterParser)->parse(implode(' or ', array_fill(0, 64, 'a eq 1'))))->not->toThrow(InvalidScimFilter::class);
});

it('says where it gave up', function (): void {
    expect(fn () => (new ScimFilterParser)->parse('userName eq "a" and'))
        ->toThrow(InvalidScimFilter::class, 'position 20');
});

it('builds the node types the tree is made of', function (): void {
    $node = (new ScimFilterParser)->parse('not (a pr) or b eq true');

    expect($node)->toBeInstanceOf(LogicalNode::class)
        ->and($node->operator)->toBe(ScimLogicalOperator::Or)
        ->and($node->left)->toBeInstanceOf(NotNode::class)
        ->and($node->right)->toBeInstanceOf(ComparisonNode::class);
});

// ---------------------------------------------------------------------------
// PATCH paths (RFC 7644 §3.5.2: PATH = attrPath / valuePath [subAttr]).
// ---------------------------------------------------------------------------

it('parses PATCH paths', function (string $path, string $target, ?string $filter): void {
    $parsed = (new ScimFilterParser)->parsePath($path);

    expect($parsed->target())->toBe($target)
        ->and($parsed->filter?->toString())->toBe($filter);
})->with([
    'attribute' => ['userName', 'username', null],
    'sub-attribute' => ['name.familyName', 'name.familyname', null],
    'value filter' => ['members[value eq "2819c223"]', 'members', 'value eq "2819c223"'],
    'value filter and sub-attribute' => ['emails[type eq "work"].value', 'emails.value', 'type eq "work"'],
    'compound value filter' => ['addresses[type eq "work" and primary eq true].streetAddress', 'addresses.streetaddress', '(type eq "work" and primary eq true)'],
    'URN-qualified' => ['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber', 'employeenumber', null],
    'operator in any case' => ['emails[type EQ "work"].value', 'emails.value', 'type eq "work"'],
    'single-quoted value' => ["emails[type eq 'work'].value", 'emails.value', 'type eq "work"'],
]);

it('refuses malformed PATCH paths', function (string $path): void {
    expect(fn () => (new ScimFilterParser)->parsePath($path))->toThrow(InvalidScimFilter::class);
})->with([
    'empty' => [''],
    'unclosed filter' => ['members[value eq "x"'],
    'garbage filter' => ['emails[something we have never seen].value'],
    'trailing junk' => ['userName extra'],
    'filter after a sub-attribute' => ['name.givenName[value eq "x"]'],
]);

// ---------------------------------------------------------------------------
// In-memory evaluation of a value filter (the `[…]` of a PATCH path).
// ---------------------------------------------------------------------------

it('evaluates a value filter against one value', function (string $filter, bool $expected): void {
    $element = ['type' => 'work', 'primary' => true, 'value' => 'Dana@Corp.com'];
    $parsed = (new ScimFilterParser)->parsePath('emails['.$filter.']');

    expect((new ScimFilterEvaluator)->matches($parsed->filter ?? throw new LogicException, $element))->toBe($expected);
})->with([
    ['type eq "work"', true],
    ['type eq "WORK"', true],
    ['type eq "home"', false],
    ['primary eq true', true],
    ['primary eq false', false],
    ['type eq "work" and primary eq true', true],
    ['type eq "home" or primary eq true', true],
    ['not (type eq "home")', true],
    ['value eq "dana@corp.com"', true],
    ['value ew "@corp.com"', true],
    ['value sw "x"', false],
    ['value co "corp"', true],
    ['display pr', false],
    ['type pr', true],
    ['display eq null', true],
    ['display ne "x"', true],
    ['value gt "a"', true],
    ['primary gt true', false],
]);

it('compares case-exact sub-attributes byte for byte', function (): void {
    $filter = (new ScimFilterParser)->parsePath('members[value eq "abc"]')->filter ?? throw new LogicException;

    expect((new ScimFilterEvaluator)->matches($filter, ['value' => 'ABC']))->toBeTrue()
        ->and((new ScimFilterEvaluator)->matches($filter, ['value' => 'ABC'], ['value']))->toBeFalse();
});
