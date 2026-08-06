<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\WebAuthn;

/**
 * The attested credential embedded in `authenticatorData` (WebAuthn §6.5.1): the
 * credential id and its COSE public key.
 *
 * `publicKey` stays an array: it is the CBOR/COSE decoder's normalized output, a
 * wire structure whose keys are COSE labels that vary by key type — parsed into
 * concrete key material downstream, not modelled here.
 */
readonly class AttestedCredential
{
    /**
     * @param  array<int|string, mixed>  $publicKey
     */
    public function __construct(
        public string $id,
        public array $publicKey,
    ) {}
}
