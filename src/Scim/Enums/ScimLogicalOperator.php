<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Enums;

/**
 * The binary logical operators of a SCIM filter (RFC 7644 §3.4.2.2, Table 4). `not` is
 * unary and has its own node; precedence (`not` > `and` > `or`) is a property of the
 * parser, not of these values.
 */
enum ScimLogicalOperator: string
{
    case And = 'and';
    case Or = 'or';
}
