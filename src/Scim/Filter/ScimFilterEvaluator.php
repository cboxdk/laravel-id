<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

use Cbox\Id\Scim\Enums\ScimComparisonOperator;
use Cbox\Id\Scim\Enums\ScimLogicalOperator;
use Cbox\Id\Scim\Filter\Nodes\ComparisonNode;
use Cbox\Id\Scim\Filter\Nodes\FilterNode;
use Cbox\Id\Scim\Filter\Nodes\LogicalNode;
use Cbox\Id\Scim\Filter\Nodes\NotNode;
use Cbox\Id\Scim\Filter\Nodes\PresentNode;
use Cbox\Id\Scim\Filter\Nodes\ValuePathNode;
use Cbox\Id\Scim\Support\ScimBoolean;

/**
 * Evaluates a parsed value filter against ONE value of a multi-valued attribute, in
 * memory — the `[…]` of a PATCH path (RFC 7644 §3.5.2): which of a group's members does
 * `members[value eq "2819c223"]` select, does `emails[type eq "work"]` name the address
 * this server stores.
 *
 * Queries over stored resources are NOT evaluated here; they are translated to SQL so
 * the database does the selecting. This is for the handful of values already in hand.
 *
 * The rules follow §3.4.2.2: strings compare case-insensitively unless the attribute is
 * `caseExact` (RFC 7643 §2.2) — the caller names those — substring operators apply to
 * strings only, ordering operators to strings and numbers, and anything the value's type
 * cannot answer is simply no match. Fail closed: a PATCH that cannot tell whether a
 * value is selected must not select it.
 */
class ScimFilterEvaluator
{
    /**
     * @param  array<array-key, mixed>  $element  one value of the attribute, keyed by
     *                                            sub-attribute name (matched without
     *                                            regard to case)
     * @param  list<string>  $caseExact  sub-attributes compared byte-for-byte
     */
    public function matches(FilterNode $filter, array $element, array $caseExact = []): bool
    {
        $values = array_change_key_case($element, CASE_LOWER);
        $exact = array_map(strtolower(...), $caseExact);

        return $this->evaluate($filter, $values, $exact);
    }

    /**
     * @param  array<array-key, mixed>  $values
     * @param  list<string>  $caseExact
     */
    private function evaluate(FilterNode $node, array $values, array $caseExact): bool
    {
        return match (true) {
            $node instanceof LogicalNode => $node->operator === ScimLogicalOperator::And
                ? $this->evaluate($node->left, $values, $caseExact) && $this->evaluate($node->right, $values, $caseExact)
                : $this->evaluate($node->left, $values, $caseExact) || $this->evaluate($node->right, $values, $caseExact),
            $node instanceof NotNode => ! $this->evaluate($node->operand, $values, $caseExact),
            $node instanceof PresentNode => self::present($values[$node->path->canonical()] ?? null),
            $node instanceof ComparisonNode => $this->compare(
                $values[$node->path->canonical()] ?? null,
                $node->operator,
                $node->value,
                in_array($node->path->canonical(), $caseExact, true),
            ),
            // A nested value path cannot be expressed inside brackets (the parser
            // refuses it); any other node type is one this evaluator does not know.
            $node instanceof ValuePathNode => false,
            default => false,
        };
    }

    private static function present(mixed $value): bool
    {
        return match (true) {
            $value === null, $value === '', $value === [] => false,
            default => true,
        };
    }

    private function compare(mixed $actual, ScimComparisonOperator $operator, string|int|float|bool|null $expected, bool $caseExact): bool
    {
        // `eq null` / `ne null`: equality with "no value".
        if ($expected === null) {
            return match ($operator) {
                ScimComparisonOperator::Equal => ! self::present($actual),
                ScimComparisonOperator::NotEqual => self::present($actual),
                default => false,
            };
        }

        if (! self::present($actual)) {
            // An absent value is not equal to anything that is present.
            return $operator === ScimComparisonOperator::NotEqual;
        }

        if (is_bool($actual)) {
            $wanted = ScimBoolean::parse($expected);

            return match ($operator) {
                ScimComparisonOperator::Equal => $wanted !== null && $actual === $wanted,
                ScimComparisonOperator::NotEqual => $wanted === null || $actual !== $wanted,
                default => false,
            };
        }

        if ((is_int($actual) || is_float($actual)) && (is_int($expected) || is_float($expected))) {
            return $this->ordered($actual <=> $expected, $operator);
        }

        if (! is_string($actual) || ! is_string($expected)) {
            return $operator === ScimComparisonOperator::NotEqual;
        }

        if (! $caseExact) {
            $actual = mb_strtolower($actual);
            $expected = mb_strtolower($expected);
        }

        return match ($operator) {
            ScimComparisonOperator::Contains => str_contains($actual, $expected),
            ScimComparisonOperator::StartsWith => str_starts_with($actual, $expected),
            ScimComparisonOperator::EndsWith => str_ends_with($actual, $expected),
            default => $this->ordered(strcmp($actual, $expected), $operator),
        };
    }

    private function ordered(int $comparison, ScimComparisonOperator $operator): bool
    {
        return match ($operator) {
            ScimComparisonOperator::Equal => $comparison === 0,
            ScimComparisonOperator::NotEqual => $comparison !== 0,
            ScimComparisonOperator::GreaterThan => $comparison > 0,
            ScimComparisonOperator::GreaterThanOrEqual => $comparison >= 0,
            ScimComparisonOperator::LessThan => $comparison < 0,
            ScimComparisonOperator::LessThanOrEqual => $comparison <= 0,
            default => false,
        };
    }
}
