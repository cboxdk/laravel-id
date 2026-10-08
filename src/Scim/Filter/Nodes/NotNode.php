<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter\Nodes;

/**
 * `not (FILTER)` — "The filter is a match if the expression evaluates to false." The
 * grammar requires the parentheses (`*1"not" "(" FILTER ")"`), so there is no bare
 * `not attr eq value` form to be ambiguous about.
 */
readonly class NotNode implements FilterNode
{
    public function __construct(public FilterNode $operand) {}

    public function toString(): string
    {
        return 'not ('.$this->operand->toString().')';
    }
}
