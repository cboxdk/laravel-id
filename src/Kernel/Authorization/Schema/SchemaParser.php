<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidSchema;

/**
 * THE SCHEMA LANGUAGE — what a person writes to describe their authorization model.
 *
 *     # Documents live in folders; a folder's viewers can read everything in it.
 *     type user
 *
 *     type group
 *       relation member: [user, group#member]
 *
 *     type folder
 *       relation parent: [folder]
 *       relation owner: [user]
 *       relation editor: [user, group#member] or owner
 *       relation viewer: [user, group#member] or editor or viewer from parent
 *
 * One `type` per resource type, its `relation`s indented below it (the indentation is for
 * the reader; a relation belongs to the type above it). A relation is decided by:
 *
 *  - `[user, group#member]` — the subjects a tuple may name on it directly;
 *  - `owner` — another relation on the same object (a computed userset);
 *  - `viewer from parent` — a relation on the objects the `parent` tuples point at;
 *  - `a or b`, `a and b`, `a but not b` — union, intersection, exclusion, with
 *    parentheses to mix them (`or` and `and` never mix without them, so nobody has to
 *    remember which binds tighter).
 *
 * `#` begins a comment where it starts a line or follows a space; `group#member` is not
 * one. The parser reports EVERY error it finds, by line, then {@see SchemaValidator}
 * checks what the names refer to — so one save shows a person everything to fix.
 */
final class SchemaParser
{
    /** A schema longer than this is refused before it is read. */
    public const int MAX_LENGTH = 65_536;

    private const array KEYWORDS = ['type', 'relation', 'or', 'and', 'but', 'not', 'from'];

    /** @var list<string> */
    private array $tokens = [];

    private int $position = 0;

    public function __construct(private readonly SchemaValidator $validator = new SchemaValidator) {}

    /**
     * Parse and validate. The schema it returns is one every check can be evaluated
     * against.
     *
     * @throws InvalidSchema
     */
    public function parse(string $source): AuthorizationSchema
    {
        if (strlen($source) > self::MAX_LENGTH) {
            throw new InvalidSchema([new SchemaError(0, 'The schema is longer than '.self::MAX_LENGTH.' bytes.')]);
        }

        $errors = [];
        /** @var array<string, int> $lines type => the line it is defined on */
        $lines = [];
        /** @var array<string, array<string, RelationDefinition>> $relations */
        $relations = [];
        $current = null;

        foreach (preg_split('/\r\n|\r|\n/', $source) ?: [] as $index => $raw) {
            $number = $index + 1;
            $text = trim(self::withoutComment($raw));

            if ($text === '') {
                continue;
            }

            if (preg_match('/^type\s+(\S+)$/', $text, $match) === 1) {
                $current = $match[1];

                if (isset($lines[$current])) {
                    $errors[] = new SchemaError($number, "`{$current}` is defined twice.");
                    $current = null;

                    continue;
                }

                $lines[$current] = $number;
                $relations[$current] = [];

                continue;
            }

            if (preg_match('/^relation\s+([^\s:]+)\s*:\s*(.*)$/', $text, $match) === 1) {
                if ($current === null) {
                    $errors[] = new SchemaError($number, 'A relation must follow the `type` it belongs to.');

                    continue;
                }

                $name = $match[1];

                if (isset($relations[$current][$name])) {
                    $errors[] = new SchemaError($number, "`{$name}` is defined twice on `{$current}`.");

                    continue;
                }

                try {
                    $rewrite = $this->expression($match[2]);
                } catch (SchemaSyntaxError $error) {
                    $errors[] = new SchemaError($number, $error->getMessage());

                    continue;
                }

                $relations[$current][$name] = new RelationDefinition($name, $rewrite, $number);

                continue;
            }

            $errors[] = new SchemaError($number, str_starts_with($text, 'relation')
                ? 'A relation is written `relation name: definition`.'
                : 'Expected `type name` or `relation name: definition`.');
        }

        if ($lines === [] && $errors === []) {
            $errors[] = new SchemaError(0, 'The schema defines no types.');
        }

        $definitions = [];

        foreach ($lines as $name => $line) {
            $definitions[$name] = new TypeDefinition($name, $relations[$name] ?? [], $line);
        }

        $schema = new AuthorizationSchema($definitions);

        $errors = [...$errors, ...$this->validator->validate($schema)];

        if ($errors !== []) {
            usort($errors, static fn (SchemaError $a, SchemaError $b): int => $a->line <=> $b->line);

            throw new InvalidSchema($errors);
        }

        return $schema;
    }

    /**
     * @throws SchemaSyntaxError
     */
    private function expression(string $text): Rewrite
    {
        $this->position = 0;
        preg_match_all('/\[|\]|,|#|\(|\)|[^\s\[\],#()]+/', $text, $matches);
        $this->tokens = $matches[0];

        if ($this->tokens === []) {
            throw new SchemaSyntaxError('The relation has no definition.');
        }

        $rewrite = $this->union();

        if ($this->peek() !== null) {
            throw new SchemaSyntaxError("Unexpected `{$this->peek()}`.");
        }

        return $rewrite;
    }

    /**
     * operand (('or' | 'and') operand)* ['but' 'not' operand]
     *
     * @throws SchemaSyntaxError
     */
    private function union(): Rewrite
    {
        $operands = [$this->operand()];
        $operator = null;

        while (in_array($this->peek(), ['or', 'and'], true)) {
            $word = (string) $this->next();

            if ($operator !== null && $word !== $operator) {
                throw new SchemaSyntaxError('`or` and `and` cannot be mixed without parentheses.');
            }

            $operator = $word;
            $operands[] = $this->operand();
        }

        $node = match (true) {
            count($operands) === 1 => $operands[0],
            $operator === 'and' => new IntersectionOf($operands),
            default => new UnionOf($operands),
        };

        if ($this->peek() === 'but') {
            $this->next();
            $this->expect('not');
            $node = new ButNot($node, $this->operand());

            if ($this->peek() === 'but') {
                throw new SchemaSyntaxError('Only one `but not` per expression — use parentheses for more.');
            }
        }

        return $node;
    }

    /**
     * @throws SchemaSyntaxError
     */
    private function operand(): Rewrite
    {
        $token = $this->next();

        if ($token === null) {
            throw new SchemaSyntaxError('The definition ends where an operand was expected.');
        }

        if ($token === '[') {
            return $this->directTypes();
        }

        if ($token === '(') {
            $inner = $this->union();
            $this->expect(')');

            return $inner;
        }

        $name = $this->name($token);

        if ($this->peek() === 'from') {
            $this->next();
            $tupleset = $this->name($this->next());

            return new RelationFromTupleset($name, $tupleset);
        }

        return new ComputedRelation($name);
    }

    /**
     * @throws SchemaSyntaxError
     */
    private function directTypes(): DirectlyRelated
    {
        $types = [];

        while (true) {
            $type = $this->name($this->next());
            $relation = null;

            if ($this->peek() === '#') {
                $this->next();
                $relation = $this->name($this->next());
            }

            $types[] = new DirectType($type, $relation);
            $separator = $this->next();

            if ($separator === ']') {
                return new DirectlyRelated($types);
            }

            if ($separator !== ',') {
                throw new SchemaSyntaxError('A list of types is written `[user, group#member]`.');
            }
        }
    }

    /**
     * @throws SchemaSyntaxError
     */
    private function name(?string $token): string
    {
        if ($token === null) {
            throw new SchemaSyntaxError('The definition ends where a name was expected.');
        }

        if (in_array($token, self::KEYWORDS, true) || in_array($token, ['[', ']', ',', '#', '(', ')'], true)) {
            throw new SchemaSyntaxError("Expected a name, found `{$token}`.");
        }

        return $token;
    }

    /**
     * @throws SchemaSyntaxError
     */
    private function expect(string $token): void
    {
        $found = $this->next();

        if ($found !== $token) {
            throw new SchemaSyntaxError("Expected `{$token}`".($found === null ? ' before the end of the line.' : ", found `{$found}`."));
        }
    }

    private function peek(): ?string
    {
        return $this->tokens[$this->position] ?? null;
    }

    private function next(): ?string
    {
        return $this->tokens[$this->position++] ?? null;
    }

    /** A `#` that starts the line or follows whitespace begins a comment; `group#member` does not. */
    private static function withoutComment(string $line): string
    {
        return (string) preg_replace('/(^|\s)#.*$/', '$1', $line);
    }
}
