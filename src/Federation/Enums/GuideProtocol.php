<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

use Cbox\Id\Federation\IdentityProviderGuides;

/**
 * The protocol an enterprise identity provider guide sets up.
 *
 * A new enum rather than cases on {@see FederationProtocol}, which a host may `match`
 * exhaustively and which describes something else: the providers WE sign in to, where
 * the difference between OIDC and plain OAuth 2.0 decides what can be trusted. A guide
 * describes the other direction — the customer's identity provider signing its people in
 * to us — where the choice is SAML 2.0 or OpenID Connect and plain OAuth 2.0 never
 * arises. See {@see IdentityProviderGuides}.
 */
enum GuideProtocol: string
{
    case Saml = 'saml';
    case Oidc = 'oidc';

    public function label(): string
    {
        return match ($this) {
            self::Saml => 'SAML 2.0',
            self::Oidc => 'OpenID Connect',
        };
    }

    /** The connection type a guide of this protocol ends up creating. */
    public function connectionType(): ConnectionType
    {
        return match ($this) {
            self::Saml => ConnectionType::Saml,
            self::Oidc => ConnectionType::Oidc,
        };
    }
}
