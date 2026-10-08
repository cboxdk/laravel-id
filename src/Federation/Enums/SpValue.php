<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

use Cbox\Id\Federation\ValueObjects\GuideField;
use Cbox\Id\Federation\ValueObjects\ServiceProviderValues;

/**
 * One of OUR values an administrator copies into THEIR identity provider's admin screen.
 *
 * The whole point of a setup guide is the mapping from these to the IdP's field labels —
 * "Reply URL (Assertion Consumer Service URL)" in one console, "Single sign-on URL" in
 * another, for the same URL of ours. The cases are the values a guide can ask for; the
 * host supplies what they are for one connection through {@see ServiceProviderValues}.
 *
 * The string values are the keys the hosted console has always used for these, so a
 * host that already renders guides from arrays keeps its keys.
 */
enum SpValue: string
{
    /** SAML Assertion Consumer Service URL — `/sso/saml/{connection}/acs`. */
    case AcsUrl = 'acs_url';

    /** SAML SP entity ID (audience). */
    case EntityId = 'entity_id';

    /** OIDC redirect URI — `/sso/oidc/{connection}/callback`. */
    case RedirectUri = 'redirect_uri';

    /**
     * A regular expression matching exactly the ACS URL — OneLogin's
     * "ACS (Consumer) URL Validator" wants one rather than the URL itself.
     */
    case AcsUrlPattern = 'acs_regex';

    /** SAML Single Logout URL — `/sso/saml/{connection}/slo`. */
    case SloUrl = 'slo_url';

    /** Our SP metadata URL — `/sso/saml/{connection}/metadata` — for IdPs that import it. */
    case SpMetadataUrl = 'sp_metadata_url';

    /** Where an IdP tile should start a sign-in — `/sso/saml/{connection}/login`. */
    case LoginUrl = 'login_url';

    /** Our SCIM 2.0 base URL — `/scim/v2`. */
    case ScimBaseUrl = 'scim_base_url';

    /**
     * The host part of the SCIM base URL alone, for an IdP that asks for host and path
     * separately (Oracle's "Host Name").
     */
    case ScimHost = 'scim_host';

    /** The path part of the SCIM base URL alone (Oracle's "Base URI"). */
    case ScimBasePath = 'scim_base_path';

    /** The SCIM bearer token we minted for the directory. */
    case ScimToken = 'scim_token';

    /** A value that is the same for everybody, carried on the {@see GuideField} itself. */
    case Literal = 'literal';

    /** Whether the value is a secret the console should show once and mask afterwards. */
    public function isSecret(): bool
    {
        return $this === self::ScimToken;
    }
}
