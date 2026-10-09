<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Fga;

use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;

/**
 * Tuples held in memory, indexed both ways. For tests, and for evaluating a model against
 * a handful of tuples without storing them.
 */
final class InMemoryTupleReader implements TupleReader
{
    /** @var array<string, array<string, SubjectRef>> resource#relation => subject => subject */
    private array $forward = [];

    /** @var array<string, array<string, Tuple>> subject => tuple => tuple */
    private array $reverse = [];

    /**
     * @param  iterable<Tuple>  $tuples
     */
    public function __construct(iterable $tuples = [])
    {
        foreach ($tuples as $tuple) {
            $this->add($tuple);
        }
    }

    public function add(Tuple $tuple): void
    {
        $this->forward[self::node($tuple->resource->type, $tuple->resource->id, $tuple->relation)][(string) $tuple->subject] = $tuple->subject;
        $this->reverse[(string) $tuple->subject][$tuple->key()] = $tuple;
    }

    public function has(string $type, string $id, string $relation, SubjectRef $subject): bool
    {
        return isset($this->forward[self::node($type, $id, $relation)][(string) $subject]);
    }

    public function direct(string $type, string $id, string $relation, SubjectRef $subject): array
    {
        return [$this->has($type, $id, $relation, $subject), $this->usersets($type, $id, $relation)];
    }

    public function usersets(string $type, string $id, string $relation): array
    {
        return array_values(array_filter($this->subjects($type, $id, $relation), static fn (SubjectRef $subject): bool => $subject->isUserset()));
    }

    public function subjects(string $type, string $id, string $relation): array
    {
        return array_values($this->forward[self::node($type, $id, $relation)] ?? []);
    }

    public function naming(SubjectRef $subject, ?string $resourceType = null, ?string $relation = null): array
    {
        return array_values(array_filter(
            $this->reverse[(string) $subject] ?? [],
            static fn (Tuple $tuple): bool => ($resourceType === null || $tuple->resource->type === $resourceType)
                && ($relation === null || $tuple->relation === $relation),
        ));
    }

    private static function node(string $type, string $id, string $relation): string
    {
        return $type.':'.$id.'#'.$relation;
    }
}
