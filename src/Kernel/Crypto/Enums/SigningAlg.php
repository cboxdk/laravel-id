<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Enums;

/**
 * Asymmetric signing algorithms supported for JWT issuance.
 *
 * Deliberately a closed set — no `none`, no symmetric (HS*) algorithms — which
 * structurally rules out `alg=none` and RS↔HS confusion at the type level.
 */
enum SigningAlg: string
{
    case RS256 = 'RS256';
    case ES256 = 'ES256';
    case EdDSA = 'EdDSA';

    public function jwkKeyType(): string
    {
        return match ($this) {
            self::RS256 => 'RSA',
            self::ES256 => 'EC',
            self::EdDSA => 'OKP',
        };
    }
}
