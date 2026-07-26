<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Saml;

use Cbox\Id\Federation\ValueObjects\SamlConnectionConfig;
use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\ValueObjects\SigningMaterial;
use OneLogin\Saml2\Settings;
use Throwable;

/**
 * Builds the onelogin/php-saml {@see Settings} for a connection from its parsed
 * config — the single place the SP<->IdP relationship is described. Shared by the
 * assertion validator (ACS), the SP metadata endpoint, SP-initiated login
 * (AuthnRequest) and Single Logout (SLO), so all four agree on entity ids,
 * endpoints and security policy.
 *
 * The config arrives as a {@see SamlConnectionConfig}: field presence and shape are
 * settled by its `fromArray()`, so this class only maps typed fields onto php-saml's
 * array schema (a third-party API boundary) and decides security policy.
 *
 * The SP half carries KEY MATERIAL — the same platform signing key the IdP role
 * publishes. Without it php-saml silently degrades: `logoutResponseSigned`
 * defaults to false (Okta/Entra with "validate logout response signature" then
 * reject our LogoutResponse and leave the user with a live IdP session), the SP
 * metadata carries no `KeyDescriptor`, and an `EncryptedAssertion` — what
 * Salesforce and Shibboleth send by default — cannot be decrypted at all.
 */
class SamlSettings
{
    public static function for(SamlConnectionConfig $config): Settings
    {
        return new Settings(self::toArray($config), true);
    }

    /**
     * @param  bool  $requireSignedMessages  enforce a signature on the whole
     *                                       inbound message (used for SLO, where the message — not an assertion — is
     *                                       the security boundary, so an unsigned LogoutRequest must be rejected).
     * @return array<string, mixed>
     */
    public static function toArray(SamlConnectionConfig $config, bool $requireSignedMessages = false): array
    {
        $sp = [
            'entityId' => $config->spEntityId,
            'assertionConsumerService' => ['url' => $config->spAcsUrl],
        ];

        $sls = $config->slsUrl();
        if ($sls !== null) {
            $sp['singleLogoutService'] = ['url' => $sls];
        }

        $certificates = $config->signingCertificates();

        $idp = [
            'entityId' => $config->idpEntityId,
            'singleSignOnService' => ['url' => $config->idpSsoUrl],
            'x509cert' => $certificates[0],
        ];

        // Key rollover: Okta and Entra publish TWO signing certificates while a
        // rotation is in flight and switch over without warning. php-saml tries
        // every cert in `x509certMulti['signing']`, so keeping them all is the
        // difference between a seamless rollover and a tenant-wide login outage.
        if (count($certificates) > 1) {
            $idp['x509certMulti'] = ['signing' => $certificates];
        }

        if ($config->idpSloUrl !== null) {
            $idp['singleLogoutService'] = ['url' => $config->idpSloUrl];
        }

        $security = [
            'wantAssertionsSigned' => true,
            'wantMessagesSigned' => $requireSignedMessages,
            'requestedAuthnContext' => false,

            // php-saml never compares Destination for equality: it is always a
            // `strncmp`, and this flag only chooses WHICH string's length bounds it
            // (Response.php:287). Off, it truncates to the received URL, so any
            // Destination that EXTENDS our ACS passes — `…/acs?tenant=other` and
            // `…/acs/2` are both accepted at `…/acs`, which in a multi-tenant SP is
            // an assertion accepted at the wrong endpoint. On, it truncates to the
            // Destination instead, so that direction is closed — but a Destination
            // that is a PREFIX of the received URL (`https://sp.example` for an ACS
            // of `https://sp.example/saml/acs`) still passes. Neither setting is an
            // exact match; this is the safer of the two halves, so it stays on.
            //
            // The cost of "on" is real and worth knowing: the URL we hand php-saml
            // is the registered ACS with its query string dropped
            // (SamlAssertionValidator::withAcsUrl parses out only scheme/host/path),
            // so a connection whose `sp_acs_url` carries a query string now presents
            // a Destination LONGER than that URL and is refused — such connections
            // were accepted before this flag was turned on.
            'destinationStrictlyMatches' => true,
        ];

        $material = self::keyMaterial();

        if ($material !== null) {
            $sp['privateKey'] = $material->privateKeyPem;
            $sp['x509cert'] = $material->certificatePem;

            // Only claim to sign once the key is actually there — php-saml
            // refuses to build settings that promise a signature it cannot make.
            $security['logoutResponseSigned'] = true;
        }

        return [
            'strict' => true,
            'sp' => $sp,
            'idp' => $idp,
            'security' => $security,
        ];
    }

    /**
     * The platform signing material for the SP role, or null when the crypto
     * kernel cannot produce it. Null degrades to the pre-key behaviour (no
     * KeyDescriptor, unsigned LogoutResponse) rather than breaking every SAML
     * flow — but it is not the expected path, and every deployment that has run
     * migrations has a key.
     */
    private static function keyMaterial(): ?SigningMaterial
    {
        try {
            return app(IdpKeyMaterial::class)->active();
        } catch (Throwable) {
            return null;
        }
    }
}
