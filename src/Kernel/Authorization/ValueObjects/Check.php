<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * "Does $subject have $relation on $resource?" — one fine-grained check.
 */
final readonly class Check
{
    public function __construct(
        public ResourceRef $resource,
        public string $relation,
        public SubjectRef $subject,
    ) {}

    public static function of(string $resourceType, string $resourceId, string $relation, SubjectRef $subject): self
    {
        return new self(ResourceRef::of($resourceType, $resourceId), $relation, $subject);
    }

    /** Stable across processes: what the check cache is keyed on, within one revision. */
    public function key(): string
    {
        return $this->resource->type.':'.$this->resource->id.'#'.$this->relation.'@'.$this->subject;
    }
}
