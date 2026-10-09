<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support\Fga;

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidSchema;
use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use Cbox\Id\Kernel\Authorization\Schema\SchemaParser;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Random\Engine\Mt19937;
use Random\Randomizer;

/**
 * A random, VALID schema and a random tuple graph over a small universe, from a seed — so
 * a failing case is reproducible from the seed alone.
 *
 * The schema has `user` plus three resource types, each with a tupleset `p` (pointing at
 * any resource type, so parent chains can loop) and four relations built at random from
 * every rewrite kind: direct lists with usersets, computed relations, tuple-to-userset,
 * union, intersection and exclusion. Candidates the parser refuses (an exclusion that
 * refers back to itself, a tuple-to-userset with no target) are simply drawn again; the
 * validator is tested on its own elsewhere.
 *
 * The tuples are drawn from what each relation's direct list allows, over three ids per
 * type and four users — dense enough that cycles through groups and parents are the norm.
 */
final class RandomModel
{
    public const array TYPES = ['t0', 't1', 't2'];

    public const array RELATIONS = ['r0', 'r1', 'r2', 'r3'];

    public const array IDS = ['a', 'b', 'c'];

    public const array USERS = ['u0', 'u1', 'u2', 'u3'];

    public readonly AuthorizationSchema $schema;

    public readonly string $source;

    /** @var list<Tuple> */
    public readonly array $tuples;

    private Randomizer $random;

    public function __construct(public readonly int $seed, int $tupleCount = 40)
    {
        $this->random = new Randomizer(new Mt19937($seed));

        [$this->source, $this->schema] = $this->schema();
        $this->tuples = $this->tuples($tupleCount);
    }

    /**
     * @return array<string, list<string>>
     */
    public function ids(): array
    {
        return array_fill_keys(self::TYPES, self::IDS);
    }

    /**
     * @return array{0: string, 1: AuthorizationSchema}
     */
    private function schema(): array
    {
        while (true) {
            $lines = ['type user'];

            foreach (self::TYPES as $type) {
                $lines[] = 'type '.$type;
                $lines[] = '  relation p: ['.implode(', ', $this->some(self::TYPES, 1)).']';

                foreach (self::RELATIONS as $relation) {
                    $direct = false;
                    $lines[] = '  relation '.$relation.': '.$this->expression($relation, 3, $direct);
                }
            }

            $source = implode("\n", $lines)."\n";

            try {
                return [$source, (new SchemaParser)->parse($source)];
            } catch (InvalidSchema) {
                continue;
            }
        }
    }

    /**
     * One relation's definition. A relation may hold one `[...]` list, so `$direct` says
     * whether this one has used it yet.
     */
    private function expression(string $relation, int $depth, bool &$direct = false): string
    {
        $kind = $depth === 0 ? $this->random->getInt(0, 2) : $this->random->getInt(0, 5);

        if ($kind === 0 && $direct) {
            $kind = 1;
        }

        switch ($kind) {
            case 0:
                $direct = true;

                return $this->direct();
            case 1:
                return $this->pick(array_values(array_diff(self::RELATIONS, [$relation])));
            case 2:
                return $this->pick(self::RELATIONS).' from p';
            case 3:
                return '('.$this->expression($relation, $depth - 1, $direct).') or ('.$this->expression($relation, $depth - 1, $direct).')';
            case 4:
                return '('.$this->expression($relation, $depth - 1, $direct).') and ('.$this->expression($relation, $depth - 1, $direct).')';
            default:
                return '('.$this->expression($relation, $depth - 1, $direct).') but not ('.$this->expression($relation, 0, $direct).')';
        }
    }

    private function direct(): string
    {
        $options = ['user'];

        foreach (self::TYPES as $type) {
            foreach (self::RELATIONS as $relation) {
                $options[] = $type.'#'.$relation;
            }
        }

        return '['.implode(', ', $this->some($options, 3)).']';
    }

    /**
     * @return list<Tuple>
     */
    private function tuples(int $count): array
    {
        $writable = [];

        foreach ($this->schema->types as $type) {
            foreach ($type->relations as $relation) {
                $direct = $relation->directlyRelated();

                if ($direct !== null) {
                    $writable[] = [$type->name, $relation->name, $direct->types];
                }
            }
        }

        $tuples = [];

        for ($i = 0; $i < $count; $i++) {
            [$type, $relation, $allowed] = $writable[$this->random->getInt(0, count($writable) - 1)];
            $target = $allowed[$this->random->getInt(0, count($allowed) - 1)];

            $subject = $target->type === 'user'
                ? SubjectRef::of('user', $this->pick(self::USERS))
                : SubjectRef::of($target->type, $this->pick(self::IDS), $target->relation);

            $tuple = Tuple::of($type, $this->pick(self::IDS), $relation, $subject);
            $tuples[$tuple->key()] = $tuple;
        }

        return array_values($tuples);
    }

    /**
     * @param  list<string>  $options
     * @return list<string>
     */
    private function some(array $options, int $max): array
    {
        $picked = $this->random->pickArrayKeys($options, $this->random->getInt(1, min($max, count($options))));

        return array_values(array_map(static fn (int|string $key): string => $options[(int) $key], $picked));
    }

    /**
     * @param  list<string>  $options
     */
    private function pick(array $options): string
    {
        return $options[$this->random->getInt(0, count($options) - 1)];
    }
}
