<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

enum ConnectionType: string
{
    case Saml = 'saml';
    case Oidc = 'oidc';

    /**
     * A provider that speaks OAuth 2.0 and nothing more — GitHub, Discord, Facebook.
     *
     * Kept separate from {@see self::Oidc} rather than folded into it, because the
     * difference is not a detail of configuration: there is no `id_token`, no discovery
     * document, and no signature over the claims. What may be trusted afterwards is
     * genuinely narrower, and one shared type would have let a caller reach for OIDC's
     * guarantees on a connection that cannot provide them.
     */
    case OAuth2 = 'oauth2';

    /**
     * Whether the provider hands us a signed assertion we verify ourselves.
     *
     * False for OAuth 2.0, where the assurance comes from having exchanged the code at
     * the provider's own token endpoint with our client secret, over TLS — enough to say
     * this browser controls that provider account, and nothing more.
     */
    public function verifiesSignature(): bool
    {
        return $this !== self::OAuth2;
    }
}
