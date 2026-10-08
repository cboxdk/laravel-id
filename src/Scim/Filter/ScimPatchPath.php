<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

use Cbox\Id\Scim\Filter\Nodes\FilterNode;

/**
 * A PATCH operation's `path` (RFC 7644 §3.5.2): `PATH = attrPath / valuePath [subAttr]`.
 *
 * - `userName` — {@see $attribute} only;
 * - `name.familyName` — attribute with its sub-attribute;
 * - `members[value eq "2819c223"]` — attribute plus a value {@see $filter};
 * - `emails[type eq "work"].value` — attribute, filter, and the {@see $subAttribute}
 *   of the selected value(s).
 */
readonly class ScimPatchPath
{
    public function __construct(
        public AttributePath $attribute,
        public ?FilterNode $filter = null,
        public ?string $subAttribute = null,
    ) {}

    /**
     * `attribute[.sub]` lower-cased, ignoring any filter: `emails[type eq "work"].value`
     * is `emails.value`. The filter decides WHICH value; this is WHAT is written.
     */
    public function target(): string
    {
        $name = strtolower($this->attribute->attribute);

        if ($this->attribute->subAttribute !== null) {
            return $name.'.'.strtolower($this->attribute->subAttribute);
        }

        return $this->subAttribute === null ? $name : $name.'.'.strtolower($this->subAttribute);
    }
}
