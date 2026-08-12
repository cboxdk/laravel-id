<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\ClientAssertion\ClientAssertionValidator;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;

/**
 * The authorization-server metadata document, shared by the OIDC discovery
 * endpoint (`/.well-known/openid-configuration`) and the OAuth 2.0 Authorization
 * Server Metadata endpoint (RFC 8414, `/.well-known/oauth-authorization-server`)
 * that MCP clients fetch. Both serve the same document.
 */
class ServerMetadata
{
    /**
     * The scopes this server advertises, in ONE place.
     *
     * `groups` puts this app's roles on the ID TOKEN. Advertised because a relying party
     * that authenticates the id_token — Kubernetes, Grafana, Vault — cannot discover it any
     * other way, and without it authenticates a person it can then bind no policy to.
     *
     * A CONSTANT BECAUSE THERE ARE TWO DOCUMENTS. OIDC discovery is not the only place a
     * client reads this: RFC 9728 protected-resource metadata carries `scopes_supported`
     * too, and it had its own hardcoded copy — missing `groups`, the one scope with a
     * named victim. `kubectl oidc-login` reads a document, asks for what it says, and is
     * refused by the server that said it. Two lists that must agree is one list.
     *
     * @var list<string>
     */
    public const SCOPES_SUPPORTED = ['openid', 'profile', 'email', 'offline_access', 'organizations', 'groups'];

    public static function issuer(): string
    {
        // Per-environment: discovery served at a tenant subdomain must advertise that
        // host as the issuer (and thus its jwks_uri), matching its per-env signing key.
        return app(IssuerResolver::class)->issuer();
    }

    /**
     * @return array<string, mixed>
     */
    public static function document(): array
    {
        $issuer = self::issuer();

        $document = [
            'issuer' => $issuer,
            'jwks_uri' => $issuer.'/.well-known/jwks.json',
            'token_endpoint' => $issuer.'/oauth/token',
            'introspection_endpoint' => $issuer.'/oauth/introspect',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            // OpenID Connect RP-Initiated Logout 1.0.
            'end_session_endpoint' => $issuer.'/oauth/logout',
            // RFC 9126: pushed authorization requests.
            'pushed_authorization_request_endpoint' => $issuer.'/oauth/par',
            'require_pushed_authorization_requests' => (bool) config('cbox-id.oauth.require_par', false),
            // RFC 8628: device authorization grant.
            'device_authorization_endpoint' => $issuer.'/oauth/device_authorization',
            // OIDC CIBA: client-initiated backchannel authentication (poll mode).
            'backchannel_authentication_endpoint' => $issuer.'/oauth/backchannel_authentication',
            'backchannel_token_delivery_modes_supported' => ['poll'],
            'backchannel_user_code_parameter_supported' => false,
            'response_types_supported' => ['code'],
            // Code flow delivers the response on the redirect QUERY — the only mode the
            // authorize flow actually produces. We do not advertise `fragment`: a client
            // that requested it would still receive the code on the query, an interop
            // break, so we promise only what is served.
            'response_modes_supported' => ['query'],
            'grant_types_supported' => self::grantTypes(),
            // EXACTLY WHAT ID_TOKENS ARE SIGNED WITH, taken from the endpoint that signs
            // them so the document and the signature cannot diverge.
            //
            // This was derived from the KEYSTORE, on the reasoning that the algs we hold
            // keys for are the algs we issue with. The second half was never true:
            // id_tokens are pinned to one alg. On a keystore rotated to ES256 the document
            // promised ES256 and the id_token arrived RS256, and a relying party that
            // pinned the advertised alg rejected it.
            //
            // Worse, it self-healed. `activeSigningKey()` generates a key it does not
            // find, so issuance did not fail — it minted an RS256 key on first use, after
            // which discovery advertised both algs and the symptom vanished, leaving one
            // rejected login and nothing to look at.
            //
            // The JWKS still exposes every key: other credentials do use the other algs.
            // It is only this list that is a promise about id_tokens specifically.
            'id_token_signing_alg_values_supported' => [TokenController::ID_TOKEN_ALG->value],
            'code_challenge_methods_supported' => ['S256'],
            // RFC 9449: sender-constrained (DPoP) access tokens.
            // From the validator, not restated here — see DpopProofValidator::ALLOWED_ALGS.
            'dpop_signing_alg_values_supported' => DpopProofValidator::ALLOWED_ALGS,
            'scopes_supported' => self::SCOPES_SUPPORTED,
            'subject_types_supported' => ['public'],
            // The claims the id_token / UserInfo actually carry — honest, not aspirational.
            // Includes the non-standard federation claims (email_verified is standard;
            // roles/permissions/organizations are extensions a client can rely on).
            'claims_supported' => [
                'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr',
                'at_hash', 'email', 'email_verified', 'name', 'org', 'org_name',
                'roles', 'permissions', 'organizations', 'groups',
            ],
            // The authentication context class references this IdP asserts: aal1 (a
            // single factor) and aal2 (a second factor was used at login). Read from
            // the enum that also gates `acr_values` at /authorize and stamps `acr` on
            // the id_token, so the advertisement cannot outrun what is enforced.
            'acr_values_supported' => AuthenticationContextClass::values(),
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'],
            // RFC 7523 client-assertion signing algs (private_key_jwt).
            // From the validator — see ClientAssertionValidator::ALLOWED_ALGS.
            'token_endpoint_auth_signing_alg_values_supported' => ClientAssertionValidator::ALLOWED_ALGS,

            // STATED SEPARATELY PER ENDPOINT, because they differ and RFC 8414 §2 lets
            // them. Revocation accepts a public client — the same `none` the token
            // endpoint accepts, which is how a browser SDK signs out. Introspection does
            // NOT: it answers questions about a token rather than destroying one, and an
            // unauthenticated answer to "is this token live, and whose" is an oracle.
            // Leaving both keys out meant a client had to infer the difference by trying,
            // and the answer to trying was a 401 every SDK swallows silently.
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'],
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
        ];

        // The interactive `/authorize` endpoint is the host app's responsibility;
        // advertise it only when the host has told us where it lives. Omitting the
        // key is valid per RFC 8414 rather than advertising a route we don't serve.
        //
        // Prefer the PATH form: it is joined to the per-environment issuer, so a tenant
        // on its own host advertises its OWN authorize endpoint. A single absolute URL
        // cannot — under multi-tenancy it pins every environment to one host, which is
        // both wrong and, because RFC 9207 is advertised alongside it, actively breaks
        // mix-up-hardened clients. The absolute form stays for hosts that serve
        // /authorize somewhere genuinely fixed.
        $authorizationPath = config('cbox-id.oauth.authorization_endpoint_path');
        $authorizationEndpoint = is_string($authorizationPath) && $authorizationPath !== ''
            ? $issuer.'/'.ltrim($authorizationPath, '/')
            : config('cbox-id.oauth.authorization_endpoint');

        if (is_string($authorizationEndpoint) && $authorizationEndpoint !== '') {
            $document['authorization_endpoint'] = $authorizationEndpoint;
            // RFC 9207 (`iss` on the authorization response, a mix-up defense) is a
            // property of that host-owned /authorize endpoint — only claim it when the
            // endpoint exists, so a mix-up-hardened client isn't promised an `iss` the
            // framework can't guarantee the host appends.
            $document['authorization_response_iss_parameter_supported'] = true;
        }

        // Advertise DCR only when it is actually enabled.
        if (config('cbox-id.oauth.dynamic_registration.mode', 'disabled') !== 'disabled') {
            $document['registration_endpoint'] = $issuer.'/oauth/register';
        }

        return $document;
    }

    /**
     * @return list<string>
     */
    private static function grantTypes(): array
    {
        return [
            'authorization_code',
            'client_credentials',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code',
            'urn:openid:params:grant-type:ciba',
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ];
    }
}
