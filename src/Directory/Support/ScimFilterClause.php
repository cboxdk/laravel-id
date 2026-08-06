<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Enums\ScimValueType;
use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Database\Eloquent\Builder;

/**
 * One atomic SCIM filter comparison — `attr op "value"` or `attr pr` — already
 * resolved to the database column it targets AND to the typed value that column
 * stores. Several of these combine under a single `and`/`or` in
 * {@see ScimUserFilter}. Each clause applies itself with an explicit boolean so the
 * compound query nests correctly.
 *
 * The value arrives coerced (see {@see ScimValueType}): a
 * boolean for `active`, a UTC timestamp string for `meta.lastModified`, a folded
 * string for the case-insensitive attributes. Coercion happens at PARSE time so an
 * uninterpretable literal refuses the whole filter, instead of being squashed into a
 * value here and answering with the wrong rows.
 */
readonly class ScimFilterClause
{
    public function __construct(
        public string $column,
        public string $operator,
        public string|bool|null $value,
    ) {}

    /**
     * @param  Builder<DirectoryUser>  $query
     * @param  'and'|'or'  $boolean
     */
    public function apply(Builder $query, string $boolean): void
    {
        // Escape LIKE metacharacters so a client can't widen the match with % / _.
        $like = addcslashes(is_string($this->value) ? $this->value : '', '%_\\');

        match ($this->operator) {
            'eq' => $query->where($this->column, '=', $this->value, $boolean),
            'ne' => $query->where($this->column, '!=', $this->value, $boolean),
            'gt' => $query->where($this->column, '>', $this->value, $boolean),
            'ge' => $query->where($this->column, '>=', $this->value, $boolean),
            'lt' => $query->where($this->column, '<', $this->value, $boolean),
            'le' => $query->where($this->column, '<=', $this->value, $boolean),
            'co' => $query->where($this->column, 'like', '%'.$like.'%', $boolean),
            'sw' => $query->where($this->column, 'like', $like.'%', $boolean),
            'ew' => $query->where($this->column, 'like', '%'.$like, $boolean),
            'pr' => $query->whereNotNull($this->column, $boolean),
            default => null,
        };
    }
}
