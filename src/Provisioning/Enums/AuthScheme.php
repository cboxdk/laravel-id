<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Enums;

/**
 * How the outbound SCIM client authenticates to a downstream app's endpoint.
 * Both schemes carry a Bearer token on the wire; they differ only in where that
 * token comes from.
 */
enum AuthScheme: string
{
    /** A long-lived bearer token issued by the downstream app, stored sealed. */
    case Bearer = 'bearer';

    /**
     * OAuth 2.0 client-credentials grant (RFC 6749 §4.4): exchange a sealed
     * client secret at the connection's token endpoint for a short-lived access
     * token, then present it as a bearer.
     */
    case OAuth2ClientCredentials = 'oauth2_client_credentials';
}
