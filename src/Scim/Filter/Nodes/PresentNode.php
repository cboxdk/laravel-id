<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter\Nodes;

use Cbox\Id\Scim\Filter\AttributePath;

/**
 * `attrPath pr` — "If the attribute has a non-empty or non-null value, or if it
 * contains a non-empty node for complex attributes, there is a match."
 */
readonly class PresentNode implements FilterNode
{
    public function __construct(public AttributePath $path) {}

    public function toString(): string
    {
        return $this->path->toString().' pr';
    }
}
