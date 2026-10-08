<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter\Nodes;

/**
 * One node of a parsed SCIM filter (RFC 7644 §3.4.2.2).
 *
 * The tree IS the precedence: `a or b and c` parses to `or(a, and(b, c))`, and
 * grouping parentheses leave no node of their own — they only change the shape. That
 * is why {@see toString()} renders every binary node fully parenthesised: it is how a
 * test (or a log line) can see exactly which reading the parser chose.
 */
interface FilterNode
{
    /**
     * A canonical, fully-parenthesised rendering of this node, with operators in
     * lower case and values JSON-encoded.
     */
    public function toString(): string;
}
