<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter\Nodes;

use Cbox\Id\Scim\Enums\ScimLogicalOperator;

/**
 * `FILTER and FILTER` / `FILTER or FILTER`. Chains are left-associative:
 * `a and b and c` is `and(and(a, b), c)`, which is the same set either way round.
 */
readonly class LogicalNode implements FilterNode
{
    public function __construct(
        public ScimLogicalOperator $operator,
        public FilterNode $left,
        public FilterNode $right,
    ) {}

    public function toString(): string
    {
        return '('.$this->left->toString().' '.$this->operator->value.' '.$this->right->toString().')';
    }
}
