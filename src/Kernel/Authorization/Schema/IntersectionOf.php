<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * `a and b and c` — every one of them is required.
 */
final readonly class IntersectionOf implements Rewrite
{
    /**
     * @param  list<Rewrite>  $operands  two or more
     */
    public function __construct(public array $operands) {}

    public function toArray(): array
    {
        return ['intersection' => array_map(static fn (Rewrite $operand): array => $operand->toArray(), $this->operands)];
    }

    public function toDsl(bool $nested = false): string
    {
        $text = implode(' and ', array_map(static fn (Rewrite $operand): string => $operand->toDsl(true), $this->operands));

        return $nested ? '('.$text.')' : $text;
    }

    public function children(): array
    {
        return $this->operands;
    }
}
