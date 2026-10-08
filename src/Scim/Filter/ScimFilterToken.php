<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

/**
 * One lexical token of a SCIM filter or PATCH path, with the offset it started at so
 * an error can say where.
 */
readonly class ScimFilterToken
{
    public function __construct(
        public ScimFilterTokenType $type,
        public string|int|float $value,
        public int $position,
    ) {}

    /**
     * Whether this is the bare word `$keyword`, compared without regard to case —
     * "attribute operators used in filters are case insensitive" (RFC 7644 §3.4.2.2).
     */
    public function isWord(string $keyword): bool
    {
        return $this->type === ScimFilterTokenType::Word
            && is_string($this->value)
            && strtolower($this->value) === $keyword;
    }

    public function text(): string
    {
        return (string) $this->value;
    }
}
