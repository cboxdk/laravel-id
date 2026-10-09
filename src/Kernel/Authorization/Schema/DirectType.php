<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * A subject a tuple may name directly on a relation: a plain type (`user`, any one user)
 * or a userset (`group#member`, everybody who is a member of one group).
 */
final readonly class DirectType
{
    public function __construct(
        public string $type,
        public ?string $relation = null,
    ) {}

    public function matches(string $type, ?string $relation): bool
    {
        return $this->type === $type && $this->relation === $relation;
    }

    public function toDsl(): string
    {
        return $this->relation === null ? $this->type : $this->type.'#'.$this->relation;
    }

    /**
     * @return array{type: string, relation?: string}
     */
    public function toArray(): array
    {
        return $this->relation === null
            ? ['type' => $this->type]
            : ['type' => $this->type, 'relation' => $this->relation];
    }
}
