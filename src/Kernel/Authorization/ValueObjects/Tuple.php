<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidTuple;

/**
 * One fine-grained relationship tuple, environment-wide:
 *
 *     document:readme#viewer@user:alice          alice is a viewer of the readme
 *     document:readme#viewer@group:eng#member    so is every member of group eng
 *     document:readme#parent@folder:handbook     the readme lives in the handbook folder
 *
 * The environment-wide sibling of {@see Relationship}, which is the same notation scoped
 * to one organization and used by the platform's own grants (resource access, groups).
 * A tuple carries no organization: model one as a resource (`organization:acme`) when the
 * model needs it.
 */
final readonly class Tuple
{
    public function __construct(
        public ResourceRef $resource,
        public string $relation,
        public SubjectRef $subject,
    ) {}

    public static function of(string $resourceType, string $resourceId, string $relation, SubjectRef $subject): self
    {
        return new self(ResourceRef::of($resourceType, $resourceId), $relation, $subject);
    }

    /**
     * `document:readme#viewer@user:alice`.
     *
     * @throws InvalidTuple
     */
    public static function parse(string $text): self
    {
        if (preg_match('/^([^:#@\s]+):([^#@]+)#([^:#@\s]+)@(.+)$/u', $text, $match) !== 1) {
            throw new InvalidTuple("`{$text}` is not a tuple: write `type:id#relation@type:id` or `…@type:id#relation`.");
        }

        return new self(ResourceRef::of($match[1], $match[2]), $match[3], SubjectRef::parse($match[4]));
    }

    public function key(): string
    {
        return (string) $this;
    }

    public function __toString(): string
    {
        return $this->resource->type.':'.$this->resource->id.'#'.$this->relation.'@'.$this->subject;
    }

    /**
     * @return array{resource_type: string, resource_id: string, relation: string, subject: array{type: string, id: string, relation: string|null}}
     */
    public function toArray(): array
    {
        return [
            'resource_type' => $this->resource->type,
            'resource_id' => $this->resource->id,
            'relation' => $this->relation,
            'subject' => $this->subject->toArray(),
        ];
    }
}
