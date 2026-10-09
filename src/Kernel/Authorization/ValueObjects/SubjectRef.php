<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidTuple;

/**
 * The subject side of a fine-grained tuple or check: one object (`user:alice`), or every
 * subject holding a relation on one object — a userset (`group:eng#member`).
 *
 * {@see Subject} is the plain "who is asking"; this adds the userset relation the tuple
 * notation needs. {@see self::fromSubject()} turns one into the other.
 */
final readonly class SubjectRef
{
    /** Ids are what an app already calls things: anything printable up to 128 characters, except the notation's `#` and `@`. */
    public const string ID_PATTERN = '/^[^\s#@\x00-\x1F\x7F]{1,128}$/u';

    public function __construct(
        public string $type,
        public string $id,
        public ?string $relation = null,
    ) {}

    public static function of(string $type, string $id, ?string $relation = null): self
    {
        return new self($type, $id, $relation === '' ? null : $relation);
    }

    public static function fromSubject(Subject $subject): self
    {
        return new self($subject->type, $subject->id);
    }

    /**
     * `user:alice` or `group:eng#member`.
     *
     * @throws InvalidTuple
     */
    public static function parse(string $text): self
    {
        if (preg_match('/^([^:#@\s]+):([^#@]+?)(?:#([^:#@\s]+))?$/u', $text, $match) !== 1) {
            throw new InvalidTuple("`{$text}` is not a subject: write `type:id` or `type:id#relation`.", field: 'subject');
        }

        return new self($match[1], $match[2], ($match[3] ?? '') === '' ? null : $match[3]);
    }

    public function isUserset(): bool
    {
        return $this->relation !== null;
    }

    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->id === $other->id && $this->relation === $other->relation;
    }

    public function __toString(): string
    {
        return $this->type.':'.$this->id.($this->relation === null ? '' : '#'.$this->relation);
    }

    /**
     * @return array{type: string, id: string, relation: string|null}
     */
    public function toArray(): array
    {
        return ['type' => $this->type, 'id' => $this->id, 'relation' => $this->relation];
    }
}
