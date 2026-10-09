<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

/**
 * One node of a relation's definition — the right-hand side of
 * `relation viewer: [user] or editor or viewer from parent`.
 *
 * Six kinds, the Zanzibar userset rewrites: the subjects a tuple names directly
 * ({@see DirectlyRelated}), another relation on the same object ({@see ComputedRelation}),
 * a relation on the objects a tupleset points at ({@see RelationFromTupleset}), and the
 * three set operators over those ({@see UnionOf}, {@see IntersectionOf}, {@see ButNot}).
 *
 * Every node prints back to the schema language and to JSON, so a stored schema can be
 * shown to a person and to a machine without keeping two sources.
 */
interface Rewrite
{
    /**
     * The JSON form an API answers with.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;

    /** The schema language, parenthesised when it sits inside another operator. */
    public function toDsl(bool $nested = false): string;

    /**
     * The nodes directly below this one.
     *
     * @return list<Rewrite>
     */
    public function children(): array;
}
