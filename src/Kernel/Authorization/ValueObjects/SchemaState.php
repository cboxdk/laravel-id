<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

use Cbox\Id\Kernel\Authorization\Schema\AuthorizationSchema;
use DateTimeInterface;

/**
 * An environment's authorization schema as stored: the source a person wrote (comments
 * and all), the parsed model, how many times it has been replaced, and the revision the
 * whole model is at.
 */
final readonly class SchemaState
{
    public function __construct(
        public ?string $source,
        public ?AuthorizationSchema $schema,
        public int $version,
        public ConsistencyToken $consistency,
        public ?DateTimeInterface $updatedAt,
    ) {}

    public function defined(): bool
    {
        return $this->schema !== null;
    }
}
