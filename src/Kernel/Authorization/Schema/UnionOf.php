<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * `a or b or c` — any one of them grants it.
 */
final readonly class UnionOf implements Rewrite
{
    /**
     * @param  list<Rewrite>  $operands  two or more
     */
    public function __construct(public array $operands) {}

    public function toArray(): array
    {
        return ['union' => array_map(static fn (Rewrite $operand): array => $operand->toArray(), $this->operands)];
    }

    public function toDsl(bool $nested = false): string
    {
        $text = implode(' or ', array_map(static fn (Rewrite $operand): string => $operand->toDsl(true), $this->operands));

        return $nested ? '('.$text.')' : $text;
    }

    public function children(): array
    {
        return $this->operands;
    }
}
