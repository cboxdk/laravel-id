<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Database\Eloquent\Builder;

/**
 * One atomic SCIM filter comparison — `attr op "value"` or `attr pr` — already
 * resolved to the database column it targets. Several of these combine under a
 * single `and`/`or` in {@see ScimUserFilter}. Each clause applies itself with an
 * explicit boolean so the compound query nests correctly.
 */
readonly class ScimFilterClause
{
    public function __construct(
        public string $column,
        public string $operator,
        public ?string $value,
    ) {}

    /**
     * @param  Builder<DirectoryUser>  $query
     * @param  'and'|'or'  $boolean
     */
    public function apply(Builder $query, string $boolean): void
    {
        $value = (string) $this->value;
        // Escape LIKE metacharacters so a client can't widen the match with % / _.
        $like = addcslashes($value, '%_\\');

        match ($this->operator) {
            'eq' => $this->column === 'active'
                ? $query->where('active', '=', filter_var($value, FILTER_VALIDATE_BOOLEAN), $boolean)
                : $query->where($this->column, '=', $value, $boolean),
            'ne' => $this->column === 'active'
                ? $query->where('active', '!=', filter_var($value, FILTER_VALIDATE_BOOLEAN), $boolean)
                : $query->where($this->column, '!=', $value, $boolean),
            'co' => $query->where($this->column, 'like', '%'.$like.'%', $boolean),
            'sw' => $query->where($this->column, 'like', $like.'%', $boolean),
            'ew' => $query->where($this->column, 'like', '%'.$like, $boolean),
            'pr' => $query->whereNotNull($this->column, $boolean),
            default => null,
        };
    }
}
