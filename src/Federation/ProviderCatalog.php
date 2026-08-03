<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Enums\ClientSecretKind;
use Cbox\Id\Federation\Enums\FederationProtocol;
use Cbox\Id\Federation\ValueObjects\ProviderParameter;
use Cbox\Id\Federation\ValueObjects\ProviderProfileMap;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;

/**
 * The providers an administrator can pick from a list instead of describing from memory.
 *
 * Everything here is the same for every customer: issuers, endpoints, scopes, where the
 * identity lives in the response, and how to obtain a credential. What is NOT here is
 * the client id and secret — those are the customer's, per tenant, and the catalogue
 * exists precisely so that they are the only things anyone has to supply.
 *
 * Two rules govern what may be added.
 *
 * **An OIDC entry is cheap to get wrong safely.** The issuer is checked by discovery the
 * moment the connection is saved, so a mistake fails loudly at setup with the provider's
 * own error, not silently at someone's first sign-in. **An OAuth 2.0 entry is not**:
 * nothing validates the endpoints until a person is standing in a redirect, so those are
 * only added when the endpoints and the profile shape have actually been checked.
 *
 * **Apple** is here, but it is not shaped like the others and pretending otherwise is
 * how an Apple integration breaks six months after anyone last touched it. It has no
 * secret to paste: the administrator supplies a downloaded signing key, and the secret
 * is an ES256 JWT minted per request. It also POSTs its callback and sends the person's
 * name exactly once. All three are declared on the template rather than discovered.
 */
final class ProviderCatalog
{
    /**
     * @return list<ProviderTemplate>
     */
    public static function all(): array
    {
        return [
            self::google(),
            self::microsoft(),
            self::okta(),
            self::auth0(),
            self::keycloak(),
            self::gitlab(),
            self::slack(),
            self::github(),
            self::discord(),
            self::apple(),
            self::facebook(),
        ];
    }

    public static function find(string $key): ?ProviderTemplate
    {
        foreach (self::all() as $template) {
            if ($template->key === $key) {
                return $template;
            }
        }

        return null;
    }

    /** @return list<string> */
    public static function keys(): array
    {
        return array_map(static fn (ProviderTemplate $t): string => $t->key, self::all());
    }

    private static function google(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'google',
            name: 'Google',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://accounts.google.com',
            documentationUrl: 'https://developers.google.com/identity/openid-connect/openid-connect',
            setupSteps: [
                'In the Google Cloud console, pick or create a project, then open APIs & Services → Credentials.',
                'Create credentials → OAuth client ID, and choose "Web application".',
                'Add the redirect URI shown below to "Authorised redirect URIs" — it must match exactly, including the scheme.',
                'Copy the client ID and client secret back here.',
            ],
        );
    }

    private static function microsoft(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'microsoft',
            name: 'Microsoft Entra ID',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name'),
            // The directory is part of the issuer: a token from one tenant must not
            // validate against another's. Using the shared `common` endpoint would accept
            // any Microsoft account in the world, which is not what an organization
            // connecting "our Microsoft" means.
            issuerTemplate: 'https://login.microsoftonline.com/{directory}/v2.0',
            parameters: [
                new ProviderParameter(
                    key: 'directory',
                    label: 'Directory (tenant) ID',
                    help: 'Entra admin centre → Overview. A GUID, not your domain name.',
                    example: '72f988bf-86f1-41af-91ab-2d7cd011db47',
                ),
            ],
            documentationUrl: 'https://learn.microsoft.com/entra/identity-platform/quickstart-register-app',
            setupSteps: [
                'In the Entra admin centre, open Identity → Applications → App registrations → New registration.',
                'Choose "Accounts in this organizational directory only" unless you intend to admit guests.',
                'Add the redirect URI shown below as a Web platform redirect.',
                'Under Certificates & secrets, create a client secret and copy its VALUE — not its ID; the value is shown once.',
                'Copy the Application (client) ID and the Directory (tenant) ID from Overview.',
            ],
        );
    }

    private static function okta(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'okta',
            name: 'Okta',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://{domain}',
            parameters: [
                new ProviderParameter(
                    key: 'domain',
                    label: 'Okta domain',
                    help: 'Your org URL without the scheme. If you use a custom authorization server, append /oauth2/<id>.',
                    example: 'acme.okta.com',
                ),
            ],
            documentationUrl: 'https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/',
            setupSteps: [
                'In the Okta admin console, open Applications → Create App Integration.',
                'Choose OIDC — OpenID Connect, then Web Application.',
                'Add the redirect URI shown below as a Sign-in redirect URI.',
                'Assign the people or groups who should be able to sign in — Okta admits nobody by default.',
                'Copy the Client ID and Client secret.',
            ],
        );
    }

    private static function auth0(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'auth0',
            name: 'Auth0',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://{domain}/',
            parameters: [
                new ProviderParameter(
                    key: 'domain',
                    label: 'Auth0 domain',
                    help: 'The tenant domain from your Auth0 application settings.',
                    example: 'acme.eu.auth0.com',
                ),
            ],
            documentationUrl: 'https://auth0.com/docs/get-started/applications',
            setupSteps: [
                'In the Auth0 dashboard, open Applications → Create Application → Regular Web Application.',
                'Add the redirect URI shown below to "Allowed Callback URLs".',
                'Copy the Domain, Client ID and Client Secret from the Settings tab.',
            ],
        );
    }

    private static function keycloak(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'keycloak',
            name: 'Keycloak',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://{host}/realms/{realm}',
            parameters: [
                new ProviderParameter(
                    key: 'host',
                    label: 'Keycloak host',
                    help: 'The public hostname of your Keycloak, without the scheme.',
                    example: 'sso.acme.com',
                ),
                new ProviderParameter(
                    key: 'realm',
                    label: 'Realm',
                    help: 'The realm your users live in — not the master realm.',
                    example: 'employees',
                ),
            ],
            documentationUrl: 'https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients',
            setupSteps: [
                'In the Keycloak admin console, select your realm, then Clients → Create client.',
                'Set the client type to OpenID Connect and turn Client authentication ON — a public client has no secret to give us.',
                'Add the redirect URI shown below to "Valid redirect URIs". Avoid wildcards.',
                'Copy the Client ID, and the secret from the Credentials tab.',
            ],
        );
    }

    private static function gitlab(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'gitlab',
            name: 'GitLab',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://{host}',
            parameters: [
                new ProviderParameter(
                    key: 'host',
                    label: 'GitLab host',
                    help: 'gitlab.com, or your self-managed hostname.',
                    example: 'gitlab.com',
                ),
            ],
            documentationUrl: 'https://docs.gitlab.com/ee/integration/openid_connect_provider.html',
            setupSteps: [
                'In GitLab, open your group or user Settings → Applications.',
                'Add the redirect URI shown below, and select the openid, email and profile scopes.',
                'Copy the Application ID and Secret.',
            ],
        );
    }

    private static function slack(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'slack',
            name: 'Slack',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://slack.com',
            documentationUrl: 'https://api.slack.com/authentication/sign-in-with-slack',
            setupSteps: [
                'At api.slack.com/apps, create an app for your workspace.',
                'Under OpenID Connect, add the redirect URI shown below and request the openid, email and profile scopes.',
                'Copy the Client ID and Client Secret from Basic Information.',
            ],
        );
    }

    private static function github(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'github',
            name: 'GitHub',
            protocol: FederationProtocol::OAuth2,
            // `user:email` is not optional. Without it the address is unavailable for
            // anyone who has not made it public, which is the default — see the note on
            // `emailEndpoint` below.
            scopes: ['read:user', 'user:email'],
            profile: new ProviderProfileMap(
                // The numeric id, never `login`: a GitHub username can be changed by its
                // owner and then claimed by someone else, so an account linked by login
                // is an account that can be inherited.
                subject: 'id',
                email: 'email',
                name: 'name',
                emailVerified: null,
                emailEndpoint: 'https://api.github.com/user/emails',
            ),
            authorizationEndpoint: 'https://github.com/login/oauth/authorize',
            tokenEndpoint: 'https://github.com/login/oauth/access_token',
            profileEndpoint: 'https://api.github.com/user',
            documentationUrl: 'https://docs.github.com/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app',
            setupSteps: [
                'In GitHub, open Settings → Developer settings → OAuth Apps → New OAuth App.',
                'Set the Authorization callback URL to the redirect URI shown below.',
                'Generate a client secret and copy it immediately — GitHub shows it once.',
            ],
        );
    }

    private static function discord(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'discord',
            name: 'Discord',
            protocol: FederationProtocol::OAuth2,
            scopes: ['identify', 'email'],
            profile: new ProviderProfileMap(
                subject: 'id',
                email: 'email',
                // `global_name` is the display name; `username` is the handle. Neither is
                // stable, which is why the subject is the snowflake id.
                name: 'global_name',
                emailVerified: 'verified',
            ),
            authorizationEndpoint: 'https://discord.com/oauth2/authorize',
            tokenEndpoint: 'https://discord.com/api/oauth2/token',
            profileEndpoint: 'https://discord.com/api/users/@me',
            documentationUrl: 'https://discord.com/developers/docs/topics/oauth2',
            setupSteps: [
                'At discord.com/developers/applications, create an application.',
                'Under OAuth2, add the redirect URI shown below.',
                'Copy the Client ID and Client Secret.',
            ],
        );
    }

    /**
     * Sign in with Apple.
     *
     * Three things are unlike every other entry here, and each one produces a failure
     * that looks like something else:
     *
     * - **No secret to paste.** The `client_secret` is an ES256 JWT signed with a `.p8`
     *   key, `iss` the team id, `sub` the Services ID, and a maximum lifetime of six
     *   months. Stored as a string it works, and then stops working on a day nobody
     *   changed anything.
     * - **`response_mode=form_post`.** The moment a scope beyond `openid` is requested,
     *   Apple POSTs the callback instead of redirecting with a query string. A handler
     *   written for a GET never runs, and the user sees what looks like a cancellation.
     * - **The name arrives once.** Apple sends `name` only on the FIRST authorization and
     *   never again. Discard that response and the name is gone permanently.
     *
     * The client id is the **Services ID**, not the App ID — a distinction Apple's own
     * console does little to signpost, and the most common reason a first attempt fails.
     */
    private static function apple(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'apple',
            name: 'Apple',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'name'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://appleid.apple.com',
            parameters: [
                new ProviderParameter(
                    key: 'team_id',
                    label: 'Team ID',
                    help: 'Apple Developer → Membership. Ten characters.',
                    example: 'A1B2C3D4E5',
                ),
                new ProviderParameter(
                    key: 'key_id',
                    label: 'Key ID',
                    help: 'The identifier of the Sign in with Apple key you created.',
                    example: 'ABC123DEFG',
                ),
                new ProviderParameter(
                    key: 'private_key',
                    label: 'Private key (.p8)',
                    help: 'The contents of the key file you downloaded. Apple lets you download it once.',
                    example: "-----BEGIN PRIVATE KEY-----\n…",
                ),
            ],
            secretKind: ClientSecretKind::SignedJwt,
            responseMode: 'form_post',
            profileOnFirstAuthorizationOnly: true,
            documentationUrl: 'https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/configuring_your_webpage_for_sign_in_with_apple',
            setupSteps: [
                'In the Apple Developer portal, create an App ID with Sign in with Apple enabled.',
                'Create a SERVICES ID — this is the client id, not the App ID. Enable Sign in with Apple on it.',
                'Configure the Services ID with your domain and add the redirect URI shown below. Apple refuses plain http, including localhost.',
                'Under Keys, create a key with Sign in with Apple enabled and download the .p8 file — Apple lets you download it once.',
                'Paste the key contents, the Key ID, and your Team ID here. There is no client secret to copy: we mint it.',
            ],
        );
    }

    /**
     * Facebook Login.
     *
     * Plain OAuth 2.0 on the web — the Graph API, not OIDC — so identity comes from a
     * profile fetch. Two practical notes: the API version is part of every endpoint and
     * ages out on Facebook's schedule rather than ours, and `email` is not guaranteed
     * even with the scope. A Facebook account can exist without one, and the person can
     * decline to share it, so a sign-in arriving with no address is normal rather than an
     * error.
     */
    private static function facebook(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'facebook',
            name: 'Facebook',
            protocol: FederationProtocol::OAuth2,
            scopes: ['public_profile', 'email'],
            profile: new ProviderProfileMap(subject: 'id', email: 'email', name: 'name'),
            authorizationEndpoint: 'https://www.facebook.com/v21.0/dialog/oauth',
            tokenEndpoint: 'https://graph.facebook.com/v21.0/oauth/access_token',
            profileEndpoint: 'https://graph.facebook.com/v21.0/me?fields=id,name,email',
            documentationUrl: 'https://developers.facebook.com/docs/facebook-login/web',
            setupSteps: [
                'At developers.facebook.com, create an app and add the Facebook Login product.',
                'Under Facebook Login → Settings, add the redirect URI shown below to "Valid OAuth Redirect URIs".',
                'Request the email permission — without App Review it works only for people with a role on the app.',
                'Copy the App ID and App Secret from Settings → Basic.',
            ],
        );
    }
}
