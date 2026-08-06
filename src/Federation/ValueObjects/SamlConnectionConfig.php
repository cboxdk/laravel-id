<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;

/**
 * A SAML connection's IdP/SP configuration, parsed once from the sealed blob.
 *
 * This was an `array<string, mixed>` threaded through the assertion validator, the
 * settings builder, the SP metadata endpoint, SP-initiated login and Single Logout —
 * six helpers re-reading string keys and re-validating the same shape, so adding one
 * field meant finding every reader. It is durable, admin-authored configuration, not
 * an HTTP body: the only array is the JSON at rest, and it is parsed here on the way
 * out of {@see SecretBox} and serialized back only on
 * the way in.
 *
 * Required: `idp_entity_id`, `idp_sso_url`, `idp_x509cert`, `sp_entity_id`,
 * `sp_acs_url`. A missing one is an {@see InvalidAssertion} at parse time — the same
 * error the scattered `require()` helpers raised, now raised once.
 */
readonly class SamlConnectionConfig
{
    /**
     * @param  list<string>  $idpExtraCertificates  further IdP signing certificates,
     *                                              for a rollover overlap window
     */
    public function __construct(
        public string $idpEntityId,
        public string $idpSsoUrl,
        public string $idpCertificate,
        public string $spEntityId,
        public string $spAcsUrl,
        public array $idpExtraCertificates = [],
        public ?string $idpSloUrl = null,
        public ?string $spSlsUrl = null,
        public bool $allowIdpInitiated = false,
    ) {}

    /**
     * @param  array<string, mixed>  $config  the unsealed JSON
     */
    public static function fromArray(array $config): self
    {
        return new self(
            idpEntityId: self::require($config, 'idp_entity_id'),
            idpSsoUrl: self::require($config, 'idp_sso_url'),
            idpCertificate: self::require($config, 'idp_x509cert'),
            spEntityId: self::require($config, 'sp_entity_id'),
            spAcsUrl: self::require($config, 'sp_acs_url'),
            idpExtraCertificates: self::stringList($config, 'idp_x509cert_extra'),
            idpSloUrl: self::optional($config, 'idp_slo_url'),
            spSlsUrl: self::optional($config, 'sp_sls_url'),
            // Strict `true`: IdP-initiated sign-in is opt-in, so a truthy-ish value
            // ('1', 'yes') must NOT enable it. Matches the `!== true` check this
            // replaces.
            allowIdpInitiated: ($config['allow_idp_initiated'] ?? false) === true,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'idp_entity_id' => $this->idpEntityId,
            'idp_sso_url' => $this->idpSsoUrl,
            'idp_x509cert' => $this->idpCertificate,
            'idp_x509cert_extra' => $this->idpExtraCertificates,
            'idp_slo_url' => $this->idpSloUrl,
            'sp_entity_id' => $this->spEntityId,
            'sp_acs_url' => $this->spAcsUrl,
            'sp_sls_url' => $this->spSlsUrl,
            'allow_idp_initiated' => $this->allowIdpInitiated,
        ], static fn (mixed $value): bool => $value !== null && $value !== [] && $value !== false);
    }

    /**
     * Every IdP signing certificate: the primary followed by any extras, de-duplicated.
     *
     * Key rollover: Okta and Entra publish TWO signing certificates while a rotation is
     * in flight and switch over without warning, so keeping them all is the difference
     * between a seamless rollover and a tenant-wide login outage.
     *
     * @return non-empty-list<string>
     */
    public function signingCertificates(): array
    {
        $certificates = [$this->idpCertificate];

        foreach ($this->idpExtraCertificates as $certificate) {
            if (! in_array($certificate, $certificates, true)) {
                $certificates[] = $certificate;
            }
        }

        return $certificates;
    }

    /**
     * The SP SingleLogoutService URL: explicit if configured, otherwise derived from
     * the ACS URL so the route pair `/sso/saml/{c}/acs` and `/sso/saml/{c}/slo` stay
     * in lockstep. Null when neither configured nor derivable.
     */
    public function slsUrl(): ?string
    {
        if ($this->spSlsUrl !== null) {
            return $this->spSlsUrl;
        }

        return str_ends_with($this->spAcsUrl, '/acs')
            ? substr($this->spAcsUrl, 0, -4).'/slo'
            : null;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function require(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidAssertion::make("connection config missing [{$key}]");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function optional(array $config, string $key): ?string
    {
        $value = $config[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return list<string>
     */
    private static function stringList(array $config, string $key): array
    {
        $value = $config[$key] ?? null;

        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter(
            $value,
            static fn (mixed $item): bool => is_string($item) && $item !== '',
        ));
    }
}
