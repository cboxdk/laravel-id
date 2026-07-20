<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;

/**
 * The IdP's stable identifiers and endpoint URLs, derived from the per-environment
 * issuer so metadata, the SSO endpoint and the SLO endpoint always agree with the
 * host (and the per-env signing cert). The EntityID defaults to `{issuer}/sso/saml/idp`
 * and is overridable via `config('cbox-id.saml_idp.entity_id')` (an EntityID is an
 * opaque URI and must stay stable once SPs have imported it).
 */
class IdpDescriptor
{
    /**
     * The environment's issuer base URL (no trailing slash) — the same value the
     * OAuth/OIDC layer publishes for this environment, so one tenant presents one
     * identity on its own host.
     */
    public static function issuer(): string
    {
        return app(IssuerResolver::class)->issuer();
    }

    public static function entityId(): string
    {
        $configured = config('cbox-id.saml_idp.entity_id');

        return is_string($configured) && $configured !== ''
            ? $configured
            : self::issuer().'/sso/saml/idp';
    }

    public static function ssoUrl(): string
    {
        return self::issuer().'/sso/saml/idp/sso';
    }

    public static function sloUrl(): string
    {
        return self::issuer().'/sso/saml/idp/slo';
    }

    public static function metadataUrl(): string
    {
        return self::issuer().'/sso/saml/idp/metadata';
    }

    /**
     * The X.509 subject Common Name for the self-signed IdP certificate — the
     * issuer host, falling back to a stable label when the host is not resolvable.
     */
    public static function certificateCommonName(): string
    {
        $host = parse_url(self::issuer(), PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : 'cbox-id';
    }
}
