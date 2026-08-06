<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Enums;

/**
 * How far single sign-on displaces local credentials for a tenant.
 *
 * Ordered weakest to strongest so an organization can only ever TIGHTEN what its
 * environment set ({@see self::atLeast()}).
 */
enum SsoEnforcement: string
{
    /** Local password sign-in is available as normal. */
    case Off = 'off';

    /** SSO is presented first, but a local password still works. */
    case Preferred = 'preferred';

    /**
     * SSO is the only way in — local password authentication is refused outright,
     * so an old credential cannot bypass the identity provider the tenant mandated.
     */
    case Required = 'required';

    /** Rank for tightening comparisons — higher is stricter. */
    public function rank(): int
    {
        return match ($this) {
            self::Off => 0,
            self::Preferred => 1,
            self::Required => 2,
        };
    }

    /** The stricter of the two, so an override never loosens the inherited setting. */
    public function atLeast(self $other): self
    {
        return $this->rank() >= $other->rank() ? $this : $other;
    }

    /** Whether a local password may still authenticate under this setting. */
    public function allowsPasswordLogin(): bool
    {
        return $this !== self::Required;
    }
}
