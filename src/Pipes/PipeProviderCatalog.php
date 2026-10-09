<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes;

use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Pipes\Enums\RevocationStyle;
use Cbox\Id\Pipes\Enums\TokenRequestFormat;
use Cbox\Id\Pipes\ValueObjects\PipeParameter;
use Cbox\Id\Pipes\ValueObjects\PipeProvider;
use Cbox\Id\Pipes\ValueObjects\PipeRevocation;

/**
 * The third-party services a person can connect their own account to, so an app can call
 * that service's API on their behalf.
 *
 * Everything here is the same for every customer: endpoints, the scopes worth asking for
 * by default, how the token response is shaped, how long tokens live, how they are
 * refreshed and revoked. What is NOT here is the OAuth client id and secret — those are
 * the customer's own app at the provider, stored (sealed) on each environment's pipe.
 *
 * ## Where this overlaps the sign-in catalogue
 *
 * Four of these vendors are also sign-in providers ({@see ProviderCatalog}). The NAME and,
 * for GitHub, the endpoints are read from there rather than restated, so the two lists
 * cannot drift on the facts they share. The rest is deliberately separate: Google and
 * Microsoft sign in over OpenID Connect with discovered endpoints, Slack signs in through
 * its OIDC flavour, and a pipe needs the plain OAuth 2.0 endpoints that hand out a
 * refreshable, API-scoped token instead. Pretending one entry serves both is how a pipe
 * ends up with an `id_token` and no refresh token.
 *
 * ## The rule for adding an entry
 *
 * Nothing validates these endpoints until a person is standing in a redirect — there is
 * no discovery document to check them against — so an entry is added only when its
 * endpoints, its token response shape and its revocation call have been checked against
 * the provider's own documentation, which {@see PipeProvider::$documentationUrl} names.
 */
class PipeProviderCatalog
{
    /**
     * @return list<PipeProvider>
     */
    public static function all(): array
    {
        return [
            self::github(),
            self::google(),
            self::microsoft(),
            self::slack(),
            self::salesforce(),
            self::hubspot(),
            self::linear(),
            self::notion(),
        ];
    }

    public static function find(string $key): ?PipeProvider
    {
        foreach (self::all() as $provider) {
            if ($provider->key === $key) {
                return $provider;
            }
        }

        return null;
    }

    /** @return list<string> */
    public static function keys(): array
    {
        return array_map(static fn (PipeProvider $p): string => $p->key, self::all());
    }

    /**
     * The display name, from the sign-in catalogue when the vendor is in both.
     */
    private static function nameOf(string $signInKey, string $fallback): string
    {
        return ProviderCatalog::find($signInKey)->name ?? $fallback;
    }

    /**
     * GitHub. An OAuth App's token does not expire and comes with no refresh token; a
     * GitHub App with expiring user tokens enabled answers `expires_in` (eight hours) and
     * a refresh token, and both shapes are handled the same way — the connection refreshes
     * when, and only when, there is something to refresh.
     */
    private static function github(): PipeProvider
    {
        $signIn = ProviderCatalog::find('github');

        return new PipeProvider(
            key: 'github',
            name: self::nameOf('github', 'GitHub'),
            authorizationEndpoint: $signIn->authorizationEndpoint ?? 'https://github.com/login/oauth/authorize',
            tokenEndpoint: $signIn->tokenEndpoint ?? 'https://github.com/login/oauth/access_token',
            defaultScopes: ['read:user'],
            apiBaseUrl: 'https://api.github.com',
            refreshable: true,
            revocation: new PipeRevocation('https://api.github.com/applications/{client_id}/grant', RevocationStyle::GitHubGrant),
            accountEndpoint: 'https://api.github.com/user',
            accountLabelPath: 'login',
            documentationUrl: 'https://docs.github.com/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps',
            setupSteps: [
                'In GitHub, open Settings → Developer settings → OAuth Apps (or GitHub Apps) and create a new app.',
                'Set the authorization callback URL to the redirect URI shown below.',
                'Generate a client secret and copy the client ID and secret back here.',
                'Add the scopes your app needs (for example `repo`) to this pipe. People are asked for them when they connect.',
            ],
            signInKey: 'github',
        );
    }

    /**
     * Google. A refresh token is only issued with `access_type=offline`, and only on the
     * FIRST consent unless `prompt=consent` forces the screen again — so a person who
     * reconnects after a revoked grant would otherwise come back with an access token and
     * no way to refresh it.
     */
    private static function google(): PipeProvider
    {
        return new PipeProvider(
            key: 'google',
            name: self::nameOf('google', 'Google'),
            authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenEndpoint: 'https://oauth2.googleapis.com/token',
            defaultScopes: ['openid', 'email', 'profile'],
            apiBaseUrl: 'https://www.googleapis.com',
            authorizeParameters: [
                'access_type' => 'offline',
                'prompt' => 'consent',
                'include_granted_scopes' => 'true',
            ],
            revocation: new PipeRevocation('https://oauth2.googleapis.com/revoke', RevocationStyle::Rfc7009, prefersRefreshToken: true),
            accountEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
            accountLabelPath: 'email',
            documentationUrl: 'https://developers.google.com/identity/protocols/oauth2/web-server',
            setupSteps: [
                'In the Google Cloud console, open APIs & Services → Credentials and create an OAuth client ID of type "Web application".',
                'Add the redirect URI shown below to "Authorised redirect URIs".',
                'Enable the APIs your app calls (Drive, Calendar, Gmail…) and add their scopes to the OAuth consent screen.',
                'Copy the client ID and client secret back here, and add the same scopes to this pipe.',
            ],
            signInKey: 'google',
        );
    }

    /**
     * Microsoft 365 (the Microsoft identity platform). `offline_access` is what makes it
     * issue a refresh token at all. There is no token revocation endpoint: disconnecting
     * forgets the tokens here, and the person removes the app's consent at
     * myapps.microsoft.com if they want it gone on Microsoft's side too.
     */
    private static function microsoft(): PipeProvider
    {
        return new PipeProvider(
            key: 'microsoft',
            name: 'Microsoft 365',
            authorizationEndpoint: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
            tokenEndpoint: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
            defaultScopes: ['offline_access', 'User.Read'],
            apiBaseUrl: 'https://graph.microsoft.com',
            parameters: [
                new PipeParameter(
                    key: 'tenant',
                    label: 'Tenant',
                    default: 'common',
                    pattern: '/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/',
                    help: '`common` for any work, school or personal account; `organizations` for work and school only; or one directory\'s tenant ID or domain.',
                ),
            ],
            accountEndpoint: 'https://graph.microsoft.com/v1.0/me',
            accountLabelPath: 'userPrincipalName',
            documentationUrl: 'https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow',
            setupSteps: [
                'In the Microsoft Entra admin center, open App registrations → New registration.',
                'Choose who may connect (any organizational directory, or personal accounts too) and add the redirect URI shown below as a Web platform redirect.',
                'Under Certificates & secrets, create a client secret and copy its value (not its ID).',
                'Under API permissions, add the Microsoft Graph delegated permissions your app calls, and list the same scopes on this pipe.',
            ],
            signInKey: 'microsoft',
        );
    }

    /**
     * Slack, for a USER token. Slack's v2 flow issues a bot token at the top of the
     * response and the person's own token under `authed_user` — and only for scopes asked
     * for in `user_scope`, comma-separated. Tokens expire (twelve hours) and refresh only
     * when the app has token rotation turned on; without it they are long-lived and there
     * is nothing to refresh.
     */
    private static function slack(): PipeProvider
    {
        return new PipeProvider(
            key: 'slack',
            name: self::nameOf('slack', 'Slack'),
            authorizationEndpoint: 'https://slack.com/oauth/v2/authorize',
            tokenEndpoint: 'https://slack.com/api/oauth.v2.access',
            defaultScopes: ['users:read'],
            apiBaseUrl: 'https://slack.com/api',
            scopeParameter: 'user_scope',
            scopeSeparator: ',',
            tokenResponsePath: 'authed_user',
            revocation: new PipeRevocation('https://slack.com/api/auth.revoke', RevocationStyle::BearerToken),
            accountLabelTokenPath: 'team.name',
            metadataPaths: ['team.id', 'team.name', 'authed_user.id'],
            documentationUrl: 'https://api.slack.com/authentication/oauth-v2',
            setupSteps: [
                'At api.slack.com/apps, create an app and open OAuth & Permissions.',
                'Add the redirect URI shown below, and add the User Token Scopes your app needs.',
                'Optionally turn on token rotation so tokens expire and are refreshed here.',
                'Copy the client ID and client secret from Basic Information back here.',
            ],
            signInKey: 'slack',
        );
    }

    /**
     * Salesforce. Two things the app cannot work without: `instance_url` from the token
     * response (every API call goes to the person's own org's host, not a shared one), and
     * the knowledge that the token's life is the org's session policy — Salesforce sends
     * no `expires_in`, so two hours, the default policy, is assumed.
     */
    private static function salesforce(): PipeProvider
    {
        return new PipeProvider(
            key: 'salesforce',
            name: 'Salesforce',
            authorizationEndpoint: 'https://{domain}/services/oauth2/authorize',
            tokenEndpoint: 'https://{domain}/services/oauth2/token',
            defaultScopes: ['api', 'refresh_token'],
            apiBaseUrl: '{instance_url}/services/data',
            assumedTokenLifetimeSeconds: 7200,
            parameters: [
                new PipeParameter(
                    key: 'domain',
                    label: 'Login domain',
                    default: 'login.salesforce.com',
                    pattern: '/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.(salesforce\.com|force\.com)$/',
                    help: '`login.salesforce.com` for production orgs, `test.salesforce.com` for sandboxes, or your My Domain host.',
                ),
            ],
            revocation: new PipeRevocation('https://{domain}/services/oauth2/revoke', RevocationStyle::Rfc7009, prefersRefreshToken: true),
            metadataPaths: ['instance_url', 'id'],
            documentationUrl: 'https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm',
            setupSteps: [
                'In Salesforce Setup, open App Manager → New Connected App (or External Client App) and enable OAuth settings.',
                'Set the callback URL to the redirect URI shown below and select the `api` and `refresh_token` scopes.',
                'Require PKCE if offered; it is always sent.',
                'Copy the consumer key and consumer secret back here as the client ID and secret.',
            ],
        );
    }

    /**
     * HubSpot. Access tokens live thirty minutes, so this is the pipe the background
     * refresh exists for. Revocation takes the refresh token in the URL path.
     */
    private static function hubspot(): PipeProvider
    {
        return new PipeProvider(
            key: 'hubspot',
            name: 'HubSpot',
            authorizationEndpoint: 'https://app.hubspot.com/oauth/authorize',
            tokenEndpoint: 'https://api.hubapi.com/oauth/v1/token',
            defaultScopes: ['oauth', 'crm.objects.contacts.read'],
            apiBaseUrl: 'https://api.hubapi.com',
            revocation: new PipeRevocation('https://api.hubapi.com/oauth/v1/refresh-tokens/{refresh_token}', RevocationStyle::RefreshTokenInPath),
            documentationUrl: 'https://developers.hubspot.com/docs/api/oauth-quickstart-guide',
            setupSteps: [
                'In your HubSpot developer account, create an app and open its Auth tab.',
                'Add the redirect URI shown below and select the scopes your app needs.',
                'Copy the client ID and client secret back here, and list the same scopes on this pipe.',
            ],
        );
    }

    /**
     * Linear. Scopes are comma-separated; access tokens expire and refresh.
     */
    private static function linear(): PipeProvider
    {
        return new PipeProvider(
            key: 'linear',
            name: 'Linear',
            authorizationEndpoint: 'https://linear.app/oauth/authorize',
            tokenEndpoint: 'https://api.linear.app/oauth/token',
            defaultScopes: ['read'],
            apiBaseUrl: 'https://api.linear.app/graphql',
            scopeSeparator: ',',
            revocation: new PipeRevocation('https://api.linear.app/oauth/revoke', RevocationStyle::BearerToken),
            documentationUrl: 'https://linear.app/developers/oauth-2-0-authentication',
            setupSteps: [
                'In Linear, open Settings → API → OAuth applications and create an application.',
                'Add the redirect URI shown below as a callback URL.',
                'Copy the client ID and client secret back here.',
            ],
        );
    }

    /**
     * Notion. No scopes — what the integration can read is chosen by the person on
     * Notion's own page picker — and the token endpoint takes a JSON body with HTTP Basic
     * client authentication. Tokens do not expire. There is no revocation endpoint to
     * call: the person removes the connection under Settings → Connections in Notion.
     */
    private static function notion(): PipeProvider
    {
        return new PipeProvider(
            key: 'notion',
            name: 'Notion',
            authorizationEndpoint: 'https://api.notion.com/v1/oauth/authorize',
            tokenEndpoint: 'https://api.notion.com/v1/oauth/token',
            defaultScopes: [],
            apiBaseUrl: 'https://api.notion.com/v1',
            // Notion now issues a refresh token that rotates on every refresh, but its
            // token response carries no `expires_in`: the access token is treated as
            // lasting until refused, and the refresh token is kept for when it is.
            refreshable: true,
            tokenEndpointAuthMethod: TokenEndpointAuthMethod::ClientSecretBasic,
            tokenRequestFormat: TokenRequestFormat::Json,
            authorizeParameters: ['owner' => 'user'],
            revocation: new PipeRevocation('https://api.notion.com/v1/oauth/revoke', RevocationStyle::JsonToken),
            accountLabelTokenPath: 'workspace_name',
            metadataPaths: ['workspace_id', 'workspace_name', 'bot_id'],
            documentationUrl: 'https://developers.notion.com/docs/authorization',
            setupSteps: [
                'At notion.so/my-integrations, create a PUBLIC integration.',
                'Add the redirect URI shown below under OAuth Domain & URIs.',
                'Copy the OAuth client ID and client secret back here.',
            ],
            // Notion refuses its OAuth endpoints without a version; this is the one its
            // token, refresh and revoke references name.
            requestHeaders: ['Notion-Version' => '2026-03-11'],
        );
    }
}
