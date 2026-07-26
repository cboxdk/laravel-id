<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\SamlIdp\Models\IdpEntityId;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * The IdP's stable identifiers and endpoint URLs. The ENDPOINTS are derived from
 * the per-environment issuer, so metadata, the SSO endpoint and the SLO endpoint
 * always agree with the host (and the per-env signing cert). The ENTITY ID is not:
 * it is frozen the first time it is published and read back from that row
 * afterwards.
 *
 * That asymmetry is the whole point. An EntityID is an opaque URI, and SAML SPs
 * treat it as a permanent name — they store it at import and reject any assertion
 * whose Issuer differs. Deriving it live from the issuer meant that the moment a
 * tenant verified a custom domain (which legitimately moves the issuer), the
 * EntityID moved with it and every federated SP rejected the next login at once,
 * with nothing in the domain-verification flow warning anyone. Freezing it keeps
 * the name stable while the URLs follow the host, which is exactly what SAML
 * expects. `config('cbox-id.saml_idp.entity_id')` still overrides globally, for
 * single-tenant deployments that pin their own.
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

    /**
     * The published EntityID: the configured override, else the value frozen for
     * this environment, else the derived default — which is frozen on the spot,
     * because returning it IS publishing it.
     */
    public static function entityId(): string
    {
        $configured = config('cbox-id.saml_idp.entity_id');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        return self::frozenEntityId() ?? self::freezeEntityId(self::issuer().'/sso/saml/idp');
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

    /**
     * The EntityID already frozen for the current environment, or null. A storage
     * failure (no migrations yet, read-only replica) degrades to the derived value
     * rather than taking the metadata endpoint down.
     */
    private static function frozenEntityId(): ?string
    {
        try {
            $frozen = IdpEntityId::query()->value('entity_id');
        } catch (QueryException) {
            return null;
        }

        return is_string($frozen) && $frozen !== '' ? $frozen : null;
    }

    /**
     * Freeze `$entityId` for this environment and return it. A concurrent writer
     * that got there first wins — its value is the published one, so re-read.
     */
    private static function freezeEntityId(string $entityId): string
    {
        try {
            IdpEntityId::query()->create(['entity_id' => $entityId]);
        } catch (UniqueConstraintViolationException) {
            return self::frozenEntityId() ?? $entityId;
        } catch (QueryException) {
            return $entityId;
        }

        return $entityId;
    }
}
