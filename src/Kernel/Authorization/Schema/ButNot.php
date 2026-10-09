<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * `viewer but not blocked` — the base, minus whoever the subtracted operand grants (an
 * exclusion).
 *
 * The one operator that is not monotone: adding a tuple can REMOVE access. So the schema
 * refuses a subtracted operand that depends, through any chain of relations, on the
 * relation it is subtracted from ({@see SchemaValidator}) — "you are a viewer unless you
 * are a viewer" has no answer, and an evaluator asked it would either loop or guess.
 */
final readonly class ButNot implements Rewrite
{
    public function __construct(
        public Rewrite $base,
        public Rewrite $subtract,
    ) {}

    public function toArray(): array
    {
        return ['exclusion' => ['base' => $this->base->toArray(), 'subtract' => $this->subtract->toArray()]];
    }

    public function toDsl(bool $nested = false): string
    {
        $text = $this->base->toDsl(true).' but not '.$this->subtract->toDsl(true);

        return $nested ? '('.$text.')' : $text;
    }

    public function children(): array
    {
        return [$this->base, $this->subtract];
    }
}
