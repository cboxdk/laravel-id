<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\SpValue;

/**
 * OUR values for one connection, as a setup guide shows them.
 *
 * The host fills this in — the routes and the configured entity ID are its to know — and
 * {@see GuideField::valueFrom()} picks the one each line of a guide asks for. The two
 * DERIVED values are derived here so every console derives them the same way: the
 * OneLogin validator pattern from the ACS URL, and the host and path halves of the SCIM
 * base URL for an IdP that asks for them separately.
 */
readonly class ServiceProviderValues
{
    public function __construct(
        public ?string $acsUrl = null,
        public ?string $entityId = null,
        public ?string $redirectUri = null,
        public ?string $sloUrl = null,
        public ?string $spMetadataUrl = null,
        public ?string $loginUrl = null,
        public ?string $scimBaseUrl = null,
        public ?string $scimToken = null,
    ) {}

    public function for(SpValue $value): ?string
    {
        return match ($value) {
            SpValue::AcsUrl => $this->acsUrl,
            SpValue::EntityId => $this->entityId,
            SpValue::RedirectUri => $this->redirectUri,
            SpValue::SloUrl => $this->sloUrl,
            SpValue::SpMetadataUrl => $this->spMetadataUrl,
            SpValue::LoginUrl => $this->loginUrl,
            SpValue::ScimBaseUrl => $this->scimBaseUrl,
            SpValue::ScimToken => $this->scimToken,
            SpValue::AcsUrlPattern => $this->acsUrl === null ? null : '^'.preg_quote($this->acsUrl, '/').'$',
            SpValue::ScimHost => $this->scimPart(PHP_URL_HOST),
            SpValue::ScimBasePath => $this->scimPart(PHP_URL_PATH),
            SpValue::Literal => null,
        };
    }

    private function scimPart(int $component): ?string
    {
        if ($this->scimBaseUrl === null) {
            return null;
        }

        $part = parse_url($this->scimBaseUrl, $component);

        return is_string($part) && $part !== '' ? $part : null;
    }
}
