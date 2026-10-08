<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

/**
 * How we prove to a provider's token endpoint that the code exchange is ours.
 *
 * RFC 6749 §2.3.1 allows two ways to present a client secret, and OpenID Connect Core
 * §9 names them: `client_secret_basic` (HTTP Basic, the client id and secret each
 * form-urlencoded and then joined by a colon) and `client_secret_post` (both as form
 * fields beside the code). The RFC says an authorization server MUST support Basic and
 * MAY support the body; in practice the providers we federate with split three ways:
 *
 *  - most accept either — Xero and Intuit say so in their discovery documents;
 *  - LinkedIn documents only the body form and publishes no
 *    `token_endpoint_auth_methods_supported` at all;
 *  - Bitbucket documents only Basic, and has no discovery document to say so.
 *
 * The body form is what this package has always sent, and it stays the default: a
 * change of default would move every existing connection to a method nobody tested it
 * with. Basic is used only where something positively says it is needed — the
 * catalogue entry for a plain OAuth 2.0 provider, or a discovery document that lists
 * its methods and leaves the body form out.
 *
 * The values are the registered OAuth parameter names, so they can be stored and
 * compared against a discovery document without translation.
 */
enum TokenEndpointAuthMethod: string
{
    /** `client_id` and `client_secret` as form fields in the token request body. */
    case ClientSecretPost = 'client_secret_post';

    /** `Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))`. */
    case ClientSecretBasic = 'client_secret_basic';

    /**
     * The method to use against a provider that advertises the given list.
     *
     * An empty list means the provider did not say. OIDC Discovery §3 makes Basic the
     * default in that case, but LinkedIn — the provider that does not say — accepts only
     * the body, so silence keeps the body form that has always worked. Basic is chosen
     * only when the list is present AND omits the body form AND names Basic: a provider
     * advertising methods we cannot use (`private_key_jwt` alone, say) keeps the default
     * and fails at the exchange with its own error, rather than with one we invented.
     *
     * @param  list<string>  $advertised  `token_endpoint_auth_methods_supported`
     */
    public static function forAdvertised(array $advertised): self
    {
        if ($advertised === [] || in_array(self::ClientSecretPost->value, $advertised, true)) {
            return self::ClientSecretPost;
        }

        return in_array(self::ClientSecretBasic->value, $advertised, true)
            ? self::ClientSecretBasic
            : self::ClientSecretPost;
    }

    /**
     * The `Authorization` header value for Basic, per RFC 6749 §2.3.1: each half is
     * form-urlencoded BEFORE the two are joined, so a secret containing `:` or `%` cannot
     * be split in the wrong place by the server.
     */
    public static function basicCredentials(string $clientId, string $clientSecret): string
    {
        return 'Basic '.base64_encode(urlencode($clientId).':'.urlencode($clientSecret));
    }
}
