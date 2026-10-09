<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Testing;

use Cbox\Id\Kernel\Authorization\Contracts\FineGrainedAuthorization;
use Cbox\Id\Kernel\Authorization\ValueObjects\Check;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\TupleWrite;

/**
 * Fine-grained authorization in a test, in the tuple notation — inside an environment
 * (`actingAsEnvironment()`), since the model is the environment's:
 *
 *     $this->fgaSchema("type user\ntype doc\n  relation viewer: [user]");
 *     $this->fgaWrite('doc:readme#viewer@user:alice');
 *     expect($this->fgaAllows('doc:readme#viewer@user:alice'))->toBeTrue();
 */
trait InteractsWithFineGrainedAuthorization
{
    protected function fga(): FineGrainedAuthorization
    {
        return app(FineGrainedAuthorization::class);
    }

    protected function fgaSchema(string $source): void
    {
        $this->fga()->updateSchema($source);
    }

    protected function fgaWrite(string ...$tuples): TupleWrite
    {
        return $this->fga()->writeTuples(array_values(array_map(Tuple::parse(...), $tuples)));
    }

    protected function fgaDelete(string ...$tuples): TupleWrite
    {
        return $this->fga()->writeTuples([], array_values(array_map(Tuple::parse(...), $tuples)));
    }

    /** Does the tuple `type:id#relation@subject` hold, directly or by inheritance? */
    protected function fgaAllows(string $tuple, ?string $consistency = null): bool
    {
        $parsed = Tuple::parse($tuple);

        return $this->fga()->check(new Check($parsed->resource, $parsed->relation, $parsed->subject), $consistency)->allowed;
    }

    /**
     * @return list<string>
     */
    protected function fgaResources(string $subject, string $relation, string $resourceType): array
    {
        return $this->fga()->listResources(SubjectRef::parse($subject), $relation, $resourceType, limit: 1000)->ids;
    }
}
