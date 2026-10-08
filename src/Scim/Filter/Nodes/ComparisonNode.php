<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter\Nodes;

use Cbox\Id\Scim\Enums\ScimComparisonOperator;
use Cbox\Id\Scim\Filter\AttributePath;

/**
 * `attrPath compareOp compValue` — `userName eq "bjensen"`,
 * `meta.lastModified gt "2011-05-13T04:42:34Z"`, `active eq true`.
 *
 * `compValue` is a JSON value (RFC 7644 Figure 1: "false / null / true / number /
 * string"), held here exactly as JSON typed it. A date is a JSON string; whether a
 * string is a date is a question for whoever knows the attribute's type, not the
 * parser.
 */
readonly class ComparisonNode implements FilterNode
{
    public function __construct(
        public AttributePath $path,
        public ScimComparisonOperator $operator,
        public string|int|float|bool|null $value,
    ) {}

    public function toString(): string
    {
        return $this->path->toString().' '.$this->operator->value.' '.json_encode($this->value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }
}
