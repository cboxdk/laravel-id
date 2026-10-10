<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Fga;

use Cbox\Id\Kernel\Authorization\Models\FgaTuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Illuminate\Database\Eloquent\Builder;

/**
 * One environment's tuples, read for one evaluation.
 *
 * Every query is one range read on the forward or the reverse index
 * (see the `create_fga_tables` migration), filtered by the environment EXPLICITLY as well
 * as by the model's environment scope. Answers are remembered for the life of the reader
 * — one call, or one batch of checks — because the evaluator asks the same node's
 * usersets once per subject, and a batch asks for many subjects.
 *
 * `$fresh` reads from the write connection: a consistency token asked for a revision the
 * read connection had not caught up with, so nothing about this evaluation may be read
 * from a replica.
 */
final class DatabaseTupleReader implements TupleReader
{
    /** @var array<string, list<SubjectRef>> */
    private array $subjects = [];

    /** @var array<string, list<Tuple>> */
    private array $naming = [];

    /** @var array<string, list<SubjectRef>> node => its usersets */
    private array $usersets = [];

    public function __construct(
        private readonly string $environmentId,
        private readonly bool $fresh = false,
    ) {}

    public function has(string $type, string $id, string $relation, SubjectRef $subject): bool
    {
        $key = $type.':'.$id.'#'.$relation;

        // Once the node's subjects are loaded, answer from them.
        if (isset($this->subjects[$key])) {
            foreach ($this->subjects[$key] as $named) {
                if ($named->equals($subject)) {
                    return true;
                }
            }

            return false;
        }

        return $this->query()
            ->where('resource_type', $type)
            ->where('resource_id', $id)
            ->where('relation', $relation)
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('subject_relation', $subject->relation ?? '')
            ->exists();
    }

    /**
     * One range read on the forward index: the rows naming $subject or any userset. A
     * group with ten thousand direct members costs one row here, not ten thousand.
     */
    public function direct(string $type, string $id, string $relation, SubjectRef $subject): array
    {
        $key = $type.':'.$id.'#'.$relation;

        if (isset($this->subjects[$key])) {
            return [$this->has($type, $id, $relation, $subject), $this->usersets($type, $id, $relation)];
        }

        $rows = $this->query()
            ->where('resource_type', $type)
            ->where('resource_id', $id)
            ->where('relation', $relation)
            ->where(static fn (Builder $query) => $query
                ->where(static fn (Builder $exact) => $exact
                    ->where('subject_type', $subject->type)
                    ->where('subject_id', $subject->id)
                    ->where('subject_relation', $subject->relation ?? ''))
                ->orWhere('subject_relation', '!=', ''))
            ->toBase()
            ->get(['subject_type', 'subject_id', 'subject_relation']);

        $named = false;
        $usersets = [];

        foreach ($rows as $row) {
            /** @var object{subject_type: string, subject_id: string, subject_relation: string} $row */
            $found = SubjectRef::of($row->subject_type, $row->subject_id, $row->subject_relation);

            if ($found->equals($subject)) {
                $named = true;
            }

            if ($found->isUserset()) {
                $usersets[] = $found;
            }
        }

        $this->usersets[$key] = $usersets;

        return [$named, $usersets];
    }

    public function usersets(string $type, string $id, string $relation): array
    {
        $key = $type.':'.$id.'#'.$relation;

        if (isset($this->usersets[$key])) {
            return $this->usersets[$key];
        }

        if (isset($this->subjects[$key])) {
            return $this->usersets[$key] = array_values(array_filter($this->subjects[$key], static fn (SubjectRef $subject): bool => $subject->isUserset()));
        }

        $rows = $this->query()
            ->where('resource_type', $type)
            ->where('resource_id', $id)
            ->where('relation', $relation)
            ->where('subject_relation', '!=', '')
            ->toBase()
            ->get(['subject_type', 'subject_id', 'subject_relation']);

        $usersets = [];

        foreach ($rows as $row) {
            /** @var object{subject_type: string, subject_id: string, subject_relation: string} $row */
            $usersets[] = SubjectRef::of($row->subject_type, $row->subject_id, $row->subject_relation);
        }

        return $this->usersets[$key] = $usersets;
    }

    public function subjects(string $type, string $id, string $relation): array
    {
        $key = $type.':'.$id.'#'.$relation;

        if (isset($this->subjects[$key])) {
            return $this->subjects[$key];
        }

        $rows = $this->query()
            ->where('resource_type', $type)
            ->where('resource_id', $id)
            ->where('relation', $relation)
            ->toBase()
            ->get(['subject_type', 'subject_id', 'subject_relation']);

        $subjects = [];

        foreach ($rows as $row) {
            /** @var object{subject_type: string, subject_id: string, subject_relation: string} $row */
            $subjects[] = SubjectRef::of($row->subject_type, $row->subject_id, $row->subject_relation);
        }

        return $this->subjects[$key] = $subjects;
    }

    public function naming(SubjectRef $subject, ?string $resourceType = null, ?string $relation = null): array
    {
        $key = $subject.'|'.$resourceType.'|'.$relation;

        if (isset($this->naming[$key])) {
            return $this->naming[$key];
        }

        $rows = $this->query()
            ->where('subject_type', $subject->type)
            ->where('subject_id', $subject->id)
            ->where('subject_relation', $subject->relation ?? '')
            ->when($resourceType !== null, static fn (Builder $query) => $query->where('resource_type', $resourceType))
            ->when($relation !== null, static fn (Builder $query) => $query->where('relation', $relation))
            ->toBase()
            ->get(['resource_type', 'resource_id', 'relation']);

        $tuples = [];

        foreach ($rows as $row) {
            /** @var object{resource_type: string, resource_id: string, relation: string} $row */
            $tuples[] = new Tuple(ResourceRef::of($row->resource_type, $row->resource_id), $row->relation, $subject);
        }

        return $this->naming[$key] = $tuples;
    }

    /**
     * @return Builder<FgaTuple>
     */
    private function query(): Builder
    {
        $query = FgaTuple::query()->where('environment_id', $this->environmentId);

        return $this->fresh ? $query->useWritePdo() : $query;
    }
}
