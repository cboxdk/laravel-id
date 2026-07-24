<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

/**
 * The IdP's active signing material. `privateKeyPem` is sensitive — it is opened
 * from the sealed store only for the duration of a signing call and is never
 * logged or persisted. `certificatePem` and `kid` are public.
 */
readonly class SigningMaterial
{
    public function __construct(
        public string $privateKeyPem,
        public string $certificatePem,
        public string $kid,
    ) {}
}
