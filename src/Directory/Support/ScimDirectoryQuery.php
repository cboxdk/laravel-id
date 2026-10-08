<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Enums\ScimAttributeType;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectorySort;
use Cbox\Id\Directory\ValueObjects\DirectorySearch;
use Cbox\Id\Scim\Enums\ScimComparisonOperator;
use Cbox\Id\Scim\Enums\ScimLogicalOperator;
use Cbox\Id\Scim\Enums\ScimSortOrder;
use Cbox\Id\Scim\Exceptions\InvalidScimFilter;
use Cbox\Id\Scim\Filter\AttributePath;
use Cbox\Id\Scim\Filter\Nodes\ComparisonNode;
use Cbox\Id\Scim\Filter\Nodes\FilterNode;
use Cbox\Id\Scim\Filter\Nodes\LogicalNode;
use Cbox\Id\Scim\Filter\Nodes\NotNode;
use Cbox\Id\Scim\Filter\Nodes\PresentNode;
use Cbox\Id\Scim\Filter\Nodes\ValuePathNode;
use Cbox\Id\Scim\Filter\ScimFilterEvaluator;
use Cbox\Id\Scim\Filter\ScimFilterParser;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Translates a parsed SCIM filter (RFC 7644 §3.4.2.2) into an Eloquent query, and a
 * `sortBy`/`sortOrder` pair (§3.4.2.3) into an ORDER BY, over the attributes a
 * {@see ScimQueryAttributes} set says the store holds.
 *
 * ## Two-valued logic
 *
 * SQL compares NULL to anything as UNKNOWN, and `NOT UNKNOWN` is still UNKNOWN — so a
 * naive `NOT (display_name = 'x')` silently drops every row with no display name, which
 * is not what "not" means in a SCIM filter. Every leaf here is written to be TRUE or
 * FALSE, never UNKNOWN: a comparison is guarded by `IS NOT NULL` (an absent attribute
 * matches no comparison), `ne` is `IS NULL OR <>` (an absent attribute is "not equal"),
 * and so `not (…)` and `ne` mean exactly what the RFC says on every row.
 *
 * ## Case
 *
 * `caseExact: false` attributes (RFC 7643 §2.2) compare lower-cased on both sides —
 * through their pre-folded column where one exists (`user_name_lower`, `email_lower`),
 * otherwise through `LOWER()` — so equality and ordering do not depend on the column's
 * collation, which differs between MySQL and PostgreSQL.
 *
 * ## Substrings
 *
 * `co`/`sw`/`ew` become `LIKE … ESCAPE '!'` with `%`, `_` and `!` escaped: the escape
 * character is declared rather than assumed, because SQLite has no default escape
 * character at all and a backslash would otherwise be a literal there.
 *
 * ## Nothing from the filter reaches SQL except as a binding
 *
 * Every raw fragment — `LOWER(…)`, the per-driver JSON extraction, the `CASE` of a
 * sort — is assembled from literals of {@see ScimQueryAttribute} and this class (the
 * static analyser holds every one of them to `literal-string`). Attribute names from the
 * filter only ever SELECT one of those literals; values only ever travel as bound
 * parameters.
 */
class ScimDirectoryQuery
{
    public function __construct(
        private readonly ScimQueryAttributes $attributes,
        private readonly ScimFilterEvaluator $evaluator = new ScimFilterEvaluator,
        private readonly ScimFilterParser $parser = new ScimFilterParser,
    ) {}

    /**
     * Apply a list query's `filter` and `sortBy`/`sortOrder` to `$query`. Without a
     * `sortBy` the order is the primary key — the order this store has always paged in.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     * @throws UnsupportedDirectorySort
     */
    public function apply(Builder $query, DirectorySearch $search): void
    {
        if (trim($search->filter) !== '') {
            try {
                $filter = $this->parser->parse($search->filter);
            } catch (InvalidScimFilter $e) {
                throw UnsupportedDirectoryFilter::because($e->getMessage());
            }

            $this->filter($query, $filter);
        }

        if ($search->sortBy === null || trim($search->sortBy) === '') {
            $query->orderBy($query->getModel()->getQualifiedKeyName());

            return;
        }

        try {
            $path = $this->parser->parsePath($search->sortBy);
        } catch (InvalidScimFilter) {
            throw UnsupportedDirectorySort::attribute($search->sortBy);
        }

        // `sortBy` is an attribute path (§3.10), never a value filter.
        if ($path->filter !== null) {
            throw UnsupportedDirectorySort::attribute($search->sortBy);
        }

        $this->sort($query, $path->attribute, $search->sortOrder);
    }

    /**
     * Constrain `$query` to the resources `$filter` matches. The whole filter is
     * nested in its own group, so an `or` inside it can never escape past the caller's
     * own scope (`WHERE directory_id = ? AND ( … OR … )`).
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    public function filter(Builder $query, FilterNode $filter): void
    {
        $query->where(function (Builder $group) use ($filter): void {
            $this->node($group, $filter, null);
        });
    }

    /**
     * Order `$query` by `$path`, with resources that have no value for it last when
     * ascending and first when descending (RFC 7644 §3.4.2.3), and by `id` after that so
     * pagination is stable across requests even when many resources share a value.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectorySort
     */
    public function sort(Builder $query, AttributePath $path, ScimSortOrder $order): void
    {
        $attribute = $this->attributes->resolve($path);

        // Sortable means one value per resource, held in a column: a multi-valued
        // relation or a defined-by-convention constant has nothing to order by.
        if ($attribute === null || $attribute->kind !== ScimQueryAttributeKind::Column) {
            throw UnsupportedDirectorySort::attribute($path->toString());
        }

        $driver = self::driver($query);
        $direction = $order === ScimSortOrder::Descending ? 'desc' : 'asc';

        // `CASE … END` first: resources with no value go last ascending and first
        // descending, on every engine — the engines disagree about where NULL sorts.
        $query->orderByRaw('CASE WHEN '.$attribute->isNullExpression($driver).' THEN 1 ELSE 0 END '.$direction)
            ->orderByRaw(self::value($attribute, $driver).' '.$direction)
            ->orderBy($query->getModel()->getQualifiedKeyName());
    }

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    private function node(Builder $query, FilterNode $node, ?AttributePath $parent): void
    {
        match (true) {
            $node instanceof LogicalNode => $this->logical($query, $node, $parent),
            $node instanceof NotNode => $query->whereNot(function (Builder $inner) use ($node, $parent): void {
                $this->node($inner, $node->operand, $parent);
            }),
            $node instanceof ValuePathNode => $this->valuePath($query, $node),
            $node instanceof ComparisonNode => $this->leaf($query, $node->path, $node, $parent),
            $node instanceof PresentNode => $this->leaf($query, $node->path, $node, $parent),
            default => throw UnsupportedDirectoryFilter::because('The filter contains an expression this server cannot evaluate.'),
        };
    }

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    private function logical(Builder $query, LogicalNode $node, ?AttributePath $parent): void
    {
        $query->where(function (Builder $left) use ($node, $parent): void {
            $this->node($left, $node->left, $parent);
        });

        $right = function (Builder $inner) use ($node, $parent): void {
            $this->node($inner, $node->right, $parent);
        };

        $node->operator === ScimLogicalOperator::And ? $query->where($right) : $query->orWhere($right);
    }

    /**
     * `attr[filter]`. Against a multi-valued RELATION the whole bracket is evaluated
     * inside ONE `EXISTS` subquery, so its conditions must hold for the same member.
     * Against the stored email — one element per user — the bracket is the row itself.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    private function valuePath(Builder $query, ValuePathNode $node): void
    {
        $attribute = $this->attributes->resolve($node->attribute);

        if ($attribute?->kind === ScimQueryAttributeKind::Relation) {
            $this->related($query, $attribute, $node->filter);

            return;
        }

        // Anything else must be a complex attribute whose sub-attributes the store holds
        // (`emails`, `manager`) — a bracket on `userName` names nothing.
        if ($this->attributes->resolve((new AttributePath('value'))->under($node->attribute)) === null) {
            throw UnsupportedDirectoryFilter::because(sprintf('[%s] has no sub-attributes to filter on.', $node->attribute->toString()));
        }

        $this->node($query, $node->filter, $node->attribute);
    }

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    private function leaf(Builder $query, AttributePath $path, ComparisonNode|PresentNode $node, ?AttributePath $parent): void
    {
        $absolute = $parent === null ? $path : $path->under($parent);
        $attribute = $this->resolve($absolute);

        if ($attribute->kind === ScimQueryAttributeKind::Relation) {
            // `members.value eq "x"`, `members eq "x"`: true when ANY member matches
            // (RFC 7644 §3.4.2.2 — "only one has to match").
            $sub = new AttributePath($absolute->subAttribute ?? 'value');
            $inner = $node instanceof PresentNode ? new PresentNode($sub) : new ComparisonNode($sub, $node->operator, $node->value);

            $this->related($query, $attribute, $inner);

            return;
        }

        if ($node instanceof PresentNode) {
            $this->present($query, $attribute);

            return;
        }

        if (! $attribute->type->supports($node->operator)) {
            throw UnsupportedDirectoryFilter::because(sprintf(
                'The operator "%s" cannot be applied to [%s].',
                $node->operator->value,
                $absolute->toString(),
            ));
        }

        // `eq null` / `ne null` — equality with "no value" is a presence test.
        if ($node->value === null) {
            match ($node->operator) {
                ScimComparisonOperator::Equal => $query->whereNot(fn (Builder $inner) => $this->present($inner, $attribute)),
                ScimComparisonOperator::NotEqual => $this->present($query, $attribute),
                default => throw UnsupportedDirectoryFilter::because(sprintf('[%s] cannot be ordered against null.', $absolute->toString())),
            };

            return;
        }

        if ($attribute->kind === ScimQueryAttributeKind::Constant) {
            $this->constant($query, $attribute, $node);

            return;
        }

        $value = $attribute->type->coerce($node->value)
            ?? throw UnsupportedDirectoryFilter::because(sprintf('%s is not a valid value for [%s].', json_encode($node->value), $absolute->toString()));

        $this->compare($query, $attribute, $node->operator, $value);
    }

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     */
    private function compare(Builder $query, ScimQueryAttribute $attribute, ScimComparisonOperator $operator, string|bool $value): void
    {
        $column = $attribute->builderColumn();

        // A plain column compared as stored goes through the builder, which binds
        // booleans the way each driver wants them. Anything folded or inside the JSON
        // document is compared on an expression built from literals only.
        $expression = self::value($attribute, self::driver($query));
        $plain = ! $attribute->needsFolding() && ! $attribute->isJson();
        $placeholder = '?';

        // `caseExact: true` (RFC 7643 §2.2) means byte-for-byte — but MySQL's and MariaDB's
        // default collations fold case, so `externalId eq "EXT-LEE"` would match `ext-lee`
        // there and nowhere else. Compared as binary on those engines; PostgreSQL and SQLite
        // already compare text byte-for-byte.
        if ($attribute->type === ScimAttributeType::CaseExactString && in_array(self::driver($query), ['mysql', 'mariadb'], true)) {
            $expression = 'CAST('.$expression.' AS BINARY)';
            $placeholder = 'CAST(? AS BINARY)';
            $plain = false;
        }

        if ($operator === ScimComparisonOperator::NotEqual) {
            $query->where(function (Builder $either) use ($column, $expression, $plain, $placeholder, $value): void {
                $either->whereNull($column);
                $plain ? $either->orWhere($column, '!=', $value) : $either->whereRaw($expression.' <> '.$placeholder, [$value], 'or');
            });

            return;
        }

        $query->whereNotNull($column);

        if ($operator->isSubstring()) {
            // The escape character first, so the escapes added after it stay single.
            $escaped = str_replace(['!', '%', '_'], ['!!', '!%', '!_'], is_string($value) ? $value : '');

            $pattern = match ($operator) {
                ScimComparisonOperator::Contains => '%'.$escaped.'%',
                ScimComparisonOperator::StartsWith => $escaped.'%',
                default => '%'.$escaped,
            };

            $query->whereRaw($expression.' LIKE '.$placeholder." ESCAPE '!'", [$pattern]);

            return;
        }

        $sql = match ($operator) {
            ScimComparisonOperator::GreaterThan => '>',
            ScimComparisonOperator::GreaterThanOrEqual => '>=',
            ScimComparisonOperator::LessThan => '<',
            ScimComparisonOperator::LessThanOrEqual => '<=',
            default => '=',
        };

        $plain ? $query->where($column, $sql, $value) : $query->whereRaw($expression.' '.$sql.' '.$placeholder, [$value]);
    }

    /**
     * `pr`: a value that is present AND non-empty (RFC 7644 Table 3).
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     */
    private function present(Builder $query, ScimQueryAttribute $attribute): void
    {
        $query->whereNotNull($attribute->builderColumn());

        if ($attribute->kind === ScimQueryAttributeKind::Column && $attribute->type->isString()) {
            $query->whereRaw($attribute->expression(self::driver($query))." <> ''");
        }
    }

    /**
     * A comparison against a value fixed by definition: decide it in PHP, and ask the
     * database only whether the element exists.
     *
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    private function constant(Builder $query, ScimQueryAttribute $attribute, ComparisonNode $node): void
    {
        $value = $attribute->type->coerce($node->value ?? '')
            ?? throw UnsupportedDirectoryFilter::because(sprintf('%s is not a valid value for [%s].', json_encode($node->value), $node->path->toString()));

        $constant = $attribute->constant;
        $matches = $this->evaluator->matches(
            new ComparisonNode(new AttributePath('constant'), $node->operator, $value),
            ['constant' => $constant],
        );

        if ($node->operator === ScimComparisonOperator::NotEqual) {
            // An absent element is "not equal" to anything; a present one is unequal
            // only when the constant itself differs.
            if (! $matches) {
                $query->whereNull($attribute->column);
            }

            return;
        }

        $matches ? $query->whereNotNull($attribute->column) : $query->whereRaw('1 = 0');
    }

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     *
     * @throws UnsupportedDirectoryFilter
     */
    private function related(Builder $query, ScimQueryAttribute $attribute, FilterNode $filter): void
    {
        $nested = new self($attribute->relationAttributes ?? $this->attributes, $this->evaluator);

        $query->whereHas($attribute->relation, function (Builder $related) use ($filter, $nested): void {
            $nested->node($related, $filter, null);
        });
    }

    /**
     * @throws UnsupportedDirectoryFilter
     */
    private function resolve(AttributePath $path): ScimQueryAttribute
    {
        return $this->attributes->resolve($path)
            ?? throw UnsupportedDirectoryFilter::because(sprintf('The attribute [%s] cannot be filtered on.', $path->toString()));
    }

    /**
     * The attribute's comparison value: lower-cased when it is `caseExact: false` and
     * not already stored folded.
     *
     * @return literal-string
     */
    private static function value(ScimQueryAttribute $attribute, string $driver): string
    {
        $expression = $attribute->expression($driver);

        return $attribute->needsFolding() ? 'LOWER('.$expression.')' : $expression;
    }

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     */
    private static function driver(Builder $query): string
    {
        return $query->getModel()->getConnection()->getDriverName();
    }
}
