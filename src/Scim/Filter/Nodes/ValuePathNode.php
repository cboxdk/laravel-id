<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter\Nodes;

use Cbox\Id\Scim\Filter\AttributePath;

/**
 * `attrPath "[" valFilter "]"` — a filter applied to ONE value of a multi-valued
 * attribute: `emails[type eq "work" and value co "@example.com"]` matches a user only
 * when a single email is both the work one and at example.com, not when one email is
 * the work one and a different one is at example.com.
 *
 * The paths inside {@see $filter} are relative to {@see $attribute}; read them with
 * {@see AttributePath::under()}.
 */
readonly class ValuePathNode implements FilterNode
{
    public function __construct(
        public AttributePath $attribute,
        public FilterNode $filter,
    ) {}

    public function toString(): string
    {
        return $this->attribute->toString().'['.$this->filter->toString().']';
    }
}
