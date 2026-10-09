<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Contracts;

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidConsistencyToken;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidSchema;
use Cbox\Id\Kernel\Authorization\Exceptions\InvalidTuple;
use Cbox\Id\Kernel\Authorization\Exceptions\ResolutionTooComplex;
use Cbox\Id\Kernel\Authorization\Exceptions\SchemaConflict;
use Cbox\Id\Kernel\Authorization\Exceptions\SchemaNotDefined;
use Cbox\Id\Kernel\Authorization\Exceptions\UnknownRelation;
use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use Cbox\Id\Kernel\Authorization\ValueObjects\Check;
use Cbox\Id\Kernel\Authorization\ValueObjects\CheckResult;
use Cbox\Id\Kernel\Authorization\ValueObjects\ConsistencyToken;
use Cbox\Id\Kernel\Authorization\ValueObjects\ObjectList;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\SchemaState;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Cbox\Id\Kernel\Authorization\ValueObjects\TupleFilter;
use Cbox\Id\Kernel\Authorization\ValueObjects\TuplePage;
use Cbox\Id\Kernel\Authorization\ValueObjects\TupleWrite;

/**
 * FINE-GRAINED AUTHORIZATION — an environment's own relationship model: a schema of
 * resource types and relations, the tuples an app writes against it, and checks
 * evaluated over both (Zanzibar-style; the shape of OpenFGA, SpiceDB and WorkOS FGA).
 *
 * Everything is scoped to the AMBIENT ENVIRONMENT: there is no environment argument, and
 * one environment's schema, tuples, revisions and cached answers are invisible to every
 * other. Calling it with no environment in context is a programming error.
 *
 * Reads take an optional consistency token (the one a write answered with): the answer is
 * then at least as fresh as that write. See {@see ConsistencyToken}.
 *
 * Next to the {@see RelationshipStore}: that store holds the PLATFORM's own
 * organization-scoped grants (resource access, group membership) under a fixed meaning;
 * this one holds a model the environment defines for its own app, environment-wide.
 */
interface FineGrainedAuthorization
{
    /** The schema as stored, and the revision the model is at. */
    public function schema(): SchemaState;

    /**
     * Parse and validate a schema without storing it.
     *
     * @throws InvalidSchema
     */
    public function validateSchema(string $source): AuthorizationSchema;

    /**
     * Replace the schema. Refused while tuples exist that the new one would not allow.
     *
     * @throws InvalidSchema
     * @throws SchemaConflict
     */
    public function updateSchema(string $source): SchemaState;

    /**
     * Write and delete tuples in one atomic batch, each checked against the schema.
     *
     * @param  list<Tuple>  $writes
     * @param  list<Tuple>  $deletes
     *
     * @throws InvalidTuple
     * @throws SchemaNotDefined
     */
    public function writeTuples(array $writes, array $deletes = []): TupleWrite;

    /**
     * Stored tuples matching $filter, oldest first.
     */
    public function tuples(TupleFilter $filter, int $limit = 50, ?string $after = null): TuplePage;

    /**
     * @throws SchemaNotDefined
     * @throws UnknownRelation
     * @throws ResolutionTooComplex
     * @throws InvalidConsistencyToken
     */
    public function check(Check $check, ConsistencyToken|string|null $consistency = null): CheckResult;

    /**
     * Several checks at one revision, answered in order.
     *
     * @param  list<Check>  $checks
     * @return list<CheckResult>
     *
     * @throws SchemaNotDefined
     * @throws UnknownRelation
     * @throws ResolutionTooComplex
     * @throws InvalidConsistencyToken
     */
    public function checkMany(array $checks, ConsistencyToken|string|null $consistency = null): array;

    /**
     * The $resourceType resources $subject has $relation on.
     *
     * @throws SchemaNotDefined
     * @throws UnknownRelation
     * @throws ResolutionTooComplex
     * @throws InvalidConsistencyToken
     */
    public function listResources(SubjectRef $subject, string $relation, string $resourceType, ConsistencyToken|string|null $consistency = null, int $limit = 100, ?string $after = null): ObjectList;

    /**
     * The $subjectType subjects that have $relation on $resource, usersets expanded.
     *
     * @throws SchemaNotDefined
     * @throws UnknownRelation
     * @throws ResolutionTooComplex
     * @throws InvalidConsistencyToken
     */
    public function listSubjects(ResourceRef $resource, string $relation, string $subjectType, ConsistencyToken|string|null $consistency = null, int $limit = 100, ?string $after = null): ObjectList;

    /** The token for the revision the model is at now. */
    public function revision(): ConsistencyToken;
}
