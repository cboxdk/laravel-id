<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

/**
 * An `attrPath` (RFC 7644 §3.4.2.2 Figure 1): an optional schema URN, an attribute
 * name and at most one sub-attribute —
 * `urn:ietf:params:scim:schemas:core:2.0:User:name.familyName`, `emails.value`,
 * `userName`.
 *
 * The names are kept as the client spelled them, for error messages; every
 * comparison goes through the folded accessors, because RFC 7643 §2.1 makes attribute
 * names case-insensitive and the URN is compared the same way (a URN's namespace
 * identifier is case-insensitive per RFC 8141, and no SCIM schema URN differs from
 * another only in case).
 *
 * Inside a value filter (`emails[type eq "work"]`) the paths are RELATIVE to the
 * multi-valued attribute in front of the bracket: `type` there means `emails.type`.
 * {@see under()} produces that absolute reading.
 */
readonly class AttributePath
{
    public function __construct(
        public string $attribute,
        public ?string $subAttribute = null,
        public ?string $schema = null,
    ) {}

    /**
     * `attribute` or `attribute.subAttribute`, lower-cased — the form every lookup
     * table is keyed by. The schema is deliberately not part of it; resolve the
     * schema first with {@see inSchema()}.
     */
    public function canonical(): string
    {
        return strtolower($this->subAttribute === null ? $this->attribute : $this->attribute.'.'.$this->subAttribute);
    }

    /**
     * Whether the path is qualified with exactly this schema URN.
     */
    public function inSchema(string $urn): bool
    {
        return $this->schema !== null && strtolower($this->schema) === strtolower($urn);
    }

    /**
     * This (relative) path read under the multi-valued attribute of a value filter:
     * `type` under `emails` is `emails.type`. A relative path never carries its own
     * schema or sub-attribute — the parser refuses both inside brackets — so the parent
     * supplies the schema and this path's name becomes the sub-attribute.
     */
    public function under(self $parent): self
    {
        return new self($parent->attribute, $this->attribute, $parent->schema);
    }

    /**
     * The path as written, URN included — for error messages.
     */
    public function toString(): string
    {
        $name = $this->subAttribute === null ? $this->attribute : $this->attribute.'.'.$this->subAttribute;

        return $this->schema === null ? $name : $this->schema.':'.$name;
    }
}
