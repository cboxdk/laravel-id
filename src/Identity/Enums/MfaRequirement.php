<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Enums;

/**
 * How strongly a second factor is expected of a subject.
 *
 * Ordered from weakest to strongest so an organization can only ever TIGHTEN what its
 * environment set ({@see self::atLeast()}).
 */
enum MfaRequirement: string
{
    /** No second factor is offered. */
    case Off = 'off';

    /** A subject may enrol a second factor; nothing forces them to. */
    case Optional = 'optional';

    /** A subject cannot complete sign-in until a second factor is enrolled. */
    case Required = 'required';

    /** Rank for tightening comparisons — higher is stricter. */
    public function rank(): int
    {
        return match ($this) {
            self::Off => 0,
            self::Optional => 1,
            self::Required => 2,
        };
    }

    /** The stricter of the two, so an override never loosens the inherited setting. */
    public function atLeast(self $other): self
    {
        return $this->rank() >= $other->rank() ? $this : $other;
    }
}
