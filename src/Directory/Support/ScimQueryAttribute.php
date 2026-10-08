<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Enums\ScimAttributeType;

/**
 * One SCIM attribute a directory query can filter or sort on, bound to where the store
 * actually keeps it.
 *
 * Only attributes the store HOLDS are ever described. An attribute that is accepted on
 * write and discarded (`title`, `phoneNumbers`, …) has no entry, and a filter naming it
 * is refused with `invalidFilter` — never answered as though every user, or none, had
 * the value.
 */
readonly class ScimQueryAttribute
{
    /**
     * @param  literal-string  $column  a column name, or the JSON column a path is read from
     * @param  literal-string  $jsonPath  dotted path inside the JSON column (`enterprise.department`), or ''
     * @param  literal-string  $pgPath  the same path as a PostgreSQL text-array literal body (`enterprise,department`)
     */
    private function __construct(
        public ScimQueryAttributeKind $kind,
        public ScimAttributeType $type,
        public string $column = '',
        public bool $folded = false,
        public string|bool|null $constant = null,
        public string $relation = '',
        public ?ScimQueryAttributes $relationAttributes = null,
        public string $jsonPath = '',
        public string $pgPath = '',
    ) {}

    /**
     * A real column.
     *
     * @param  literal-string  $column
     * @param  bool  $folded  the column already holds the lower-cased form (the
     *                        `*_lower` comparison columns), so the comparison must not
     *                        wrap it in LOWER() and lose the index
     */
    public static function column(string $column, ScimAttributeType $type, bool $folded = false): self
    {
        return new self(ScimQueryAttributeKind::Column, $type, $column, $folded);
    }

    /**
     * A value inside the stored `resource` JSON document.
     *
     * The path is given twice — dotted for the `$.a.b` JSON path MySQL, MariaDB and
     * SQLite use, comma-separated for PostgreSQL's `#>> '{a,b}'` — so every SQL
     * fragment built from it stays a literal of this file, never a string assembled at
     * run time (see {@see ScimDirectoryQuery}).
     *
     * @param  literal-string  $path
     * @param  literal-string  $pgPath
     */
    public static function json(string $path, string $pgPath, ScimAttributeType $type): self
    {
        return new self(ScimQueryAttributeKind::Column, $type, 'resource', jsonPath: $path, pgPath: $pgPath);
    }

    /**
     * A value fixed by definition for every element that is present; `$presence` is
     * the column whose non-null value means the element exists.
     *
     * @param  literal-string  $presence
     */
    public static function constant(string|bool $value, string $presence, ScimAttributeType $type): self
    {
        return new self(ScimQueryAttributeKind::Constant, $type, $presence, constant: $value);
    }

    /**
     * A multi-valued attribute in another table, filtered through the Eloquent
     * relation `$relation` with the sub-attributes `$attributes` describes.
     */
    public static function relation(string $relation, ScimQueryAttributes $attributes): self
    {
        return new self(ScimQueryAttributeKind::Relation, ScimAttributeType::CaseExactString, relation: $relation, relationAttributes: $attributes);
    }

    public function isJson(): bool
    {
        return $this->jsonPath !== '';
    }

    /**
     * The attribute in the query builder's own notation (`resource->enterprise->department`),
     * for the builder's null checks — which know, per driver, that a JSON `null` is
     * not a value.
     */
    public function builderColumn(): string
    {
        return $this->isJson() ? $this->column.'->'.str_replace('.', '->', $this->jsonPath) : $this->column;
    }

    /**
     * The attribute as an SQL value expression for `$driver`.
     *
     * Built from literal pieces only — the column names and paths above are literals
     * of {@see ScimQueryAttributes} — so no part of a filter ever reaches SQL except as
     * a bound parameter.
     *
     * @return literal-string
     */
    public function expression(string $driver): string
    {
        if (! $this->isJson()) {
            return $this->column;
        }

        return match ($driver) {
            'mysql', 'mariadb' => 'json_unquote(json_extract('.$this->column.", '$.".$this->jsonPath."'))",
            'pgsql' => '('.$this->column." #>> '{".$this->pgPath."}')",
            'sqlsrv' => 'json_value('.$this->column.", '$.".$this->jsonPath."')",
            default => 'json_extract('.$this->column.", '$.".$this->jsonPath."')",
        };
    }

    /**
     * An SQL condition true when the attribute has no value — a JSON `null` included,
     * which MySQL's `json_unquote()` would otherwise hand back as the string "null".
     *
     * @return literal-string
     */
    public function isNullExpression(string $driver): string
    {
        if ($this->isJson() && in_array($driver, ['mysql', 'mariadb'], true)) {
            return 'COALESCE(json_type(json_extract('.$this->column.", '$.".$this->jsonPath."')), 'NULL') = 'NULL'";
        }

        return $this->expression($driver).' IS NULL';
    }

    /**
     * Whether the database value must be lower-cased before it is compared or sorted.
     */
    public function needsFolding(): bool
    {
        return $this->type === ScimAttributeType::CaseInsensitiveString && ! $this->folded;
    }
}
