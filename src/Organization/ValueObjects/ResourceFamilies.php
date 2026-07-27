<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use InvalidArgumentException;
use JsonSerializable;

/**
 * Which resource families a user API token may touch — the token's family
 * allow-list, as a type rather than an array.
 *
 * There are three states and the whole point of this class is that they cannot
 * collapse into each other:
 *
 *   - UNRESTRICTED — no family restriction was expressed at all, so every family
 *     is allowed. This is what a `NULL` column has always meant and still means.
 *   - a NON-EMPTY list — exactly those families, nothing else.
 *   - NONE — a restriction WAS expressed and it names nothing, so no family is
 *     allowed. Stored as an empty JSON array.
 *
 * A bare `array` cannot hold that third state. `[]` reads as both "absent" and
 * "empty", and the previous implementation resolved the ambiguity the dangerous
 * way — `$families === [] ? null : $families` — so a caller asking for the most
 * restrictive token possible was handed one permitted on every family. That is
 * exactly the kind of security boundary that must be enforced by the type system
 * and not by a convention two files apart.
 *
 * ON-DISK COMPATIBILITY: `null` still means unrestricted, so every token issued
 * before this type existed keeps precisely the meaning it was issued with. Only
 * the empty array — a value the old code could never write — is new.
 */
final readonly class ResourceFamilies implements JsonSerializable
{
    /**
     * @param  list<string>|null  $families  null is UNRESTRICTED; a list (possibly
     *                                       empty) is the exhaustive allow-list.
     */
    private function __construct(private ?array $families) {}

    /** Every family — no restriction was expressed. */
    public static function unrestricted(): self
    {
        return new self(null);
    }

    /** No family at all — a restriction was expressed and it names nothing. */
    public static function none(): self
    {
        return new self([]);
    }

    /**
     * Exactly the named families. `of()` with no arguments is {@see none()} and
     * NOT {@see unrestricted()} — naming zero families is a restriction.
     */
    public static function of(string ...$families): self
    {
        return self::fromList(array_values($families));
    }

    /**
     * @param  list<string>  $families
     */
    public static function fromList(array $families): self
    {
        $normalised = [];

        foreach ($families as $family) {
            if (trim($family) === '') {
                throw new InvalidArgumentException('A resource family cannot be blank.');
            }

            if (! in_array($family, $normalised, true)) {
                $normalised[] = $family;
            }
        }

        return new self($normalised);
    }

    /**
     * Rehydrate from the stored column. `null` (and a column that was never
     * written) is unrestricted; anything else is read as an exhaustive list.
     */
    public static function fromStorage(mixed $value): self
    {
        if ($value === null) {
            return self::unrestricted();
        }

        if (! is_array($value)) {
            throw new InvalidArgumentException('Stored resource families must be null or a JSON array.');
        }

        $families = [];

        foreach ($value as $family) {
            if (! is_string($family)) {
                throw new InvalidArgumentException('Stored resource families must contain strings only.');
            }

            $families[] = $family;
        }

        return self::fromList($families);
    }

    public function isUnrestricted(): bool
    {
        return $this->families === null;
    }

    /** Whether the token may touch this family. */
    public function allows(string $family): bool
    {
        return $this->families === null || in_array($family, $this->families, true);
    }

    /**
     * The column value: `null` for unrestricted, otherwise the list — `[]`
     * included, which is the state the old array-shaped code could not express.
     *
     * @return list<string>|null
     */
    public function toStorage(): ?array
    {
        return $this->families;
    }

    /**
     * Serialises back to the wire shape the column and the introspection response
     * have always used, so a model handed straight to `response()->json()` does not
     * quietly emit an empty object where a list used to be.
     *
     * @return list<string>|null
     */
    public function jsonSerialize(): ?array
    {
        return $this->families;
    }

    public function equals(self $other): bool
    {
        return $this->families === $other->families;
    }
}
