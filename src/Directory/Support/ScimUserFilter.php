<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Database\Eloquent\Builder;

/**
 * Parses and applies the subset of SCIM 2.0 filter syntax that identity
 * providers actually send against `/Users` — overwhelmingly
 * `userName eq "x"` / `externalId eq "x"` existence checks before provisioning,
 * plus `co`/`sw`/`ew` and `pr`. Anything outside the subset returns null so the
 * caller can surface an `invalidFilter` error rather than silently mis-matching.
 */
final readonly class ScimUserFilter
{
    private const ATTRIBUTES = [
        'username' => 'resource->userName',
        'externalid' => 'external_id',
        'active' => 'active',
        'emails.value' => 'resource->email',
        'emails' => 'resource->email',
    ];

    private function __construct(
        public string $column,
        public string $operator,
        public ?string $value,
    ) {}

    public static function parse(string $filter): ?self
    {
        $filter = trim($filter);

        // Present: `attr pr`
        if (preg_match('/^(?<attr>[\w.]+)\s+pr$/i', $filter, $m) === 1) {
            $column = self::column($m['attr']);

            return $column === null ? null : new self($column, 'pr', null);
        }

        // Binary: `attr op "value"`
        if (preg_match('/^(?<attr>[\w.]+)\s+(?<op>eq|ne|co|sw|ew)\s+"(?<val>[^"]*)"$/i', $filter, $m) === 1) {
            $column = self::column($m['attr']);

            return $column === null ? null : new self($column, strtolower($m['op']), $m['val']);
        }

        return null;
    }

    /**
     * @param  Builder<DirectoryUser>  $query
     * @return Builder<DirectoryUser>
     */
    public function apply(Builder $query): Builder
    {
        $value = (string) $this->value;
        // Escape LIKE metacharacters so a client can't widen the match with % / _.
        $like = addcslashes($value, '%_\\');

        return match ($this->operator) {
            'eq' => $this->column === 'active'
                ? $query->where('active', filter_var($value, FILTER_VALIDATE_BOOLEAN))
                : $query->where($this->column, $value),
            'ne' => $query->where($this->column, '!=', $value),
            'co' => $query->where($this->column, 'like', '%'.$like.'%'),
            'sw' => $query->where($this->column, 'like', $like.'%'),
            'ew' => $query->where($this->column, 'like', '%'.$like),
            'pr' => $query->whereNotNull($this->column),
            default => $query,
        };
    }

    private static function column(string $attribute): ?string
    {
        return self::ATTRIBUTES[strtolower($attribute)] ?? null;
    }
}
