<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Enums;

enum KeyStatus: string
{
    /** Currently used to sign new tokens. */
    case Active = 'active';

    /** No longer signing, but still published in JWKS so in-flight tokens verify. */
    case Rotating = 'rotating';

    /** Removed from JWKS; kept only for audit history. */
    case Retired = 'retired';
}
