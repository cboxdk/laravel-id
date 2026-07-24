<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Enums\ServiceProviderStatus;

/**
 * Input for registering a relying SAML service provider. `attributeMappings` maps
 * an emitted SAML attribute name to the subject/user field it is read from (e.g.
 * `['email' => 'email', 'firstName' => 'given_name']`).
 */
readonly class NewServiceProvider
{
    /**
     * @param  array<string, string>  $attributeMappings
     */
    public function __construct(
        public string $entityId,
        public string $acsUrl,
        public NameIdFormat $nameIdFormat = NameIdFormat::EmailAddress,
        public string $nameIdAttribute = 'email',
        public array $attributeMappings = [],
        public ?string $certificate = null,
        public bool $wantAuthnRequestsSigned = false,
        public ServiceProviderStatus $status = ServiceProviderStatus::Active,
        public ?string $sloUrl = null,
    ) {}
}
