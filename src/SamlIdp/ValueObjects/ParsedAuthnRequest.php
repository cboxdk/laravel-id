<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use DOMDocument;

/**
 * The raw, pre-validation shape of a decoded `AuthnRequest`: what the XML says,
 * before any trust decision. The `document` is retained so an embedded XML-DSig
 * (HTTP-POST binding) can be verified against the SP certificate. Consumers must
 * still enforce SP registration, ACS match and signature policy — this object
 * asserts nothing about trust.
 */
final readonly class ParsedAuthnRequest
{
    public function __construct(
        public string $id,
        public string $issuer,
        public ?string $assertionConsumerServiceUrl,
        public ?string $nameIdFormat,
        public bool $hasSignature,
        public DOMDocument $document,
    ) {}
}
