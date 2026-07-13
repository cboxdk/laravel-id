<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Saml;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use OneLogin\Saml2\Settings;

/**
 * Builds the onelogin/php-saml {@see Settings} for a connection from its sealed
 * config — the single place the SP<->IdP relationship is described. Shared by the
 * assertion validator (ACS), the SP metadata endpoint, SP-initiated login
 * (AuthnRequest) and Single Logout (SLO), so all four agree on entity ids,
 * endpoints and security policy.
 *
 * Required config: `idp_entity_id`, `idp_sso_url`, `idp_x509cert`,
 * `sp_entity_id`, `sp_acs_url`. Optional for SLO: `idp_slo_url` (the IdP's
 * SingleLogoutService) and `sp_sls_url` (defaults to the ACS URL with a trailing
 * `/acs` rewritten to `/slo`).
 */
final class SamlSettings
{
    /**
     * @param  array<string, mixed>  $config
     */
    public static function for(array $config): Settings
    {
        return new Settings(self::toArray($config), true);
    }

    /**
     * @param  array<string, mixed>  $config
     * @param  bool  $requireSignedMessages  enforce a signature on the whole
     *                                       inbound message (used for SLO, where the message — not an assertion — is
     *                                       the security boundary, so an unsigned LogoutRequest must be rejected).
     * @return array<string, mixed>
     */
    public static function toArray(array $config, bool $requireSignedMessages = false): array
    {
        $acs = self::require($config, 'sp_acs_url');

        $sp = [
            'entityId' => self::require($config, 'sp_entity_id'),
            'assertionConsumerService' => ['url' => $acs],
        ];

        $sls = self::optional($config, 'sp_sls_url') ?? self::deriveSlsUrl($acs);
        if ($sls !== null) {
            $sp['singleLogoutService'] = ['url' => $sls];
        }

        $idp = [
            'entityId' => self::require($config, 'idp_entity_id'),
            'singleSignOnService' => ['url' => self::require($config, 'idp_sso_url')],
            'x509cert' => self::require($config, 'idp_x509cert'),
        ];

        $idpSlo = self::optional($config, 'idp_slo_url');
        if ($idpSlo !== null) {
            $idp['singleLogoutService'] = ['url' => $idpSlo];
        }

        return [
            'strict' => true,
            'sp' => $sp,
            'idp' => $idp,
            'security' => [
                'wantAssertionsSigned' => true,
                'wantMessagesSigned' => $requireSignedMessages,
                'requestedAuthnContext' => false,
            ],
        ];
    }

    /**
     * The SP SingleLogoutService URL for a connection (typed), or null if neither
     * configured nor derivable.
     *
     * @param  array<string, mixed>  $config
     */
    public static function slsUrl(array $config): ?string
    {
        $explicit = self::optional($config, 'sp_sls_url');
        if ($explicit !== null) {
            return $explicit;
        }

        $acs = self::optional($config, 'sp_acs_url');

        return $acs !== null ? self::deriveSlsUrl($acs) : null;
    }

    /**
     * The SP SingleLogoutService URL, derived from the ACS URL so the route pair
     * `/sso/saml/{c}/acs` and `/sso/saml/{c}/slo` stay in lockstep.
     */
    private static function deriveSlsUrl(string $acsUrl): ?string
    {
        if (str_ends_with($acsUrl, '/acs')) {
            return substr($acsUrl, 0, -4).'/slo';
        }

        return null;
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
}
