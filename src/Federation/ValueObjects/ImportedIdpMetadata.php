<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

/**
 * The IdP fields extracted from a SAML 2.0 metadata document — the entity id, the
 * SingleSignOnService URL, the signing certificate, and (optionally) the
 * SingleLogoutService URL. This is a PREFILL for the connection form: it carries
 * only the IdP half of the relationship (the SP half — ACS/entity id — is the
 * platform's own, derived from the connection's route), and creating the connection
 * stays an explicit admin action.
 */
readonly class ImportedIdpMetadata
{
    public function __construct(
        public string $entityId,
        public string $ssoUrl,
        public string $x509cert,
        public ?string $sloUrl = null,
    ) {}

    /** Whether every field the SAML validator requires was found in the metadata. */
    public function isComplete(): bool
    {
        return $this->entityId !== '' && $this->ssoUrl !== '' && $this->x509cert !== '';
    }

    /**
     * The connection-config keys the SAML settings/validator expect. Only the IdP
     * side — merged with the platform-generated SP keys when the connection is saved.
     *
     * @return array<string, string>
     */
    public function toConfig(): array
    {
        $config = [
            'idp_entity_id' => $this->entityId,
            'idp_sso_url' => $this->ssoUrl,
            'idp_x509cert' => $this->x509cert,
        ];

        if ($this->sloUrl !== null && $this->sloUrl !== '') {
            $config['idp_slo_url'] = $this->sloUrl;
        }

        return $config;
    }
}
