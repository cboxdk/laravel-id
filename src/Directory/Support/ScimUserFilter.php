<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Database\Eloquent\Builder;

/**
 * Parses and applies the subset of SCIM 2.0 filter syntax (RFC 7644 §3.4.2.2)
 * identity providers actually send against `/Users`: the comparison operators
 * `eq`/`ne`/`co`/`sw`/`ew` and the presence test `pr`, over a fixed set of known
 * attributes, combined by a single top-level `and` or `or`. That covers the real
 * traffic — `userName eq "x"` existence checks before provisioning, and Entra-style
 * `userName eq "x" and active eq true` — without pretending to implement the whole
 * grammar. Grouping parentheses, nested/value-path filters, and mixing `and` with
 * `or` are out of scope and return null, so the caller surfaces `invalidFilter`
 * rather than silently mis-matching.
 */
readonly class ScimUserFilter
{
    private const ATTRIBUTES = [
        'username' => 'resource->userName',
        'externalid' => 'external_id',
        'active' => 'active',
        'emails.value' => 'resource->email',
        'emails' => 'resource->email',
    ];

    // A clause is a presence test (`attr pr`) or a comparison whose value is a
    // quoted string or an unquoted boolean literal (`active eq true`, RFC 7644).
    private const CLAUSE = '(?<attr>[\w.]+)\s+(?:(?<presence>pr)|(?<op>eq|ne|co|sw|ew)\s+(?:"(?<val>[^"]*)"|(?<lit>true|false)))';

    /**
     * @param  non-empty-list<ScimFilterClause>  $clauses
     * @param  'and'|'or'  $conjunction  how the clauses combine (irrelevant for one)
     */
    private function __construct(
        public array $clauses,
        public string $conjunction,
    ) {}

    public static function parse(string $filter): ?self
    {
        $rest = trim($filter);
        $clauses = [];
        $conjunction = 'and';

        while ($rest !== '') {
            if (preg_match('/^'.self::CLAUSE.'/i', $rest, $m) !== 1) {
                return null;
            }

            $clause = self::clause($m);

            if ($clause === null) {
                return null;
            }

            $clauses[] = $clause;
            $rest = trim(substr($rest, strlen($m[0])));

            if ($rest === '') {
                break;
            }

            // Between two clauses the ONLY thing allowed is a single logical joiner,
            // and the whole expression must use one operator — mixing `and`/`or`
            // needs grouping we do not parse, so refuse it rather than guess precedence.
            if (preg_match('/^(?<join>and|or)\s+/i', $rest, $j) !== 1) {
                return null;
            }

            $join = strtolower($j['join']) === 'or' ? 'or' : 'and';

            if (count($clauses) > 1 && $join !== $conjunction) {
                return null;
            }

            $conjunction = $join;
            $rest = substr($rest, strlen($j[0]));
        }

        return $clauses === [] ? null : new self($clauses, $conjunction);
    }

    /**
     * @param  Builder<DirectoryUser>  $query
     * @return Builder<DirectoryUser>
     */
    public function apply(Builder $query): Builder
    {
        // Nest the clauses in their own group so an `or` never escapes past the
        // caller's directory scope (`WHERE directory_id = ? AND ( … OR … )`).
        return $query->where(function (Builder $group): void {
            foreach ($this->clauses as $index => $clause) {
                $clause->apply($group, $index === 0 ? 'and' : $this->conjunction);
            }
        });
    }

    /**
     * @param  array<array-key, string>  $matches
     */
    private static function clause(array $matches): ?ScimFilterClause
    {
        $column = self::ATTRIBUTES[strtolower($matches['attr'])] ?? null;

        if ($column === null) {
            return null;
        }

        if (($matches['presence'] ?? '') !== '') {
            return new ScimFilterClause($column, 'pr', null);
        }

        // An unquoted boolean literal (`lit`) wins over the quoted `val`; only one
        // of the two alternation branches ever participates in a match.
        $literal = $matches['lit'] ?? '';
        $value = $literal !== '' ? $literal : ($matches['val'] ?? '');

        return new ScimFilterClause($column, strtolower($matches['op']), $value);
    }
}
