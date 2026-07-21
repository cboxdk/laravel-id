<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;

/**
 * A public verification key: the material a resource server needs to check a JWT
 * signature, with no private component. Cheap and safe to cache — it carries only
 * public key material and its pinned algorithm.
 */
final readonly class VerificationKey
{
    public function __construct(
        public string $kid,
        public string $publicKey,
        public SigningAlg $alg,
    ) {}
}
