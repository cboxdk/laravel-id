<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * What is being accessed — a typed resource reference (e.g. document:42).
 */
final readonly class ResourceRef
{
    public function __construct(
        public string $type,
        public string $id,
    ) {}

    public static function of(string $type, string $id): self
    {
        return new self($type, $id);
    }
}
