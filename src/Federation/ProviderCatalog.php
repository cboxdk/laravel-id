<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Federation\Enums\ClientSecretKind;
use Cbox\Id\Federation\Enums\FederationProtocol;
use Cbox\Id\Federation\Enums\ProviderCapability;
use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
use Cbox\Id\Federation\ValueObjects\DirectorySetup;
use Cbox\Id\Federation\ValueObjects\IdentityProviderGuide;
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
 *
 * ## One catalogue, several capabilities
 *
 * Google and Entra are not only sign-in providers: we also read their user lists. That
 * used to live in a second registry that shared nothing with this one but the words
 * "Google" and "Microsoft", and the cost was paid by the administrator. The directory
 * screen could not show the guide that already existed here for the same provider, so
 * somebody who had just connected Google for sign-in was handed an empty form and left to
 * work out on their own that a directory needs a service account instead of an OAuth
 * client. An entry now carries what it can DO — see {@see ProviderCapability} — and the
 * directory half carries its own steps, because the two setups have nothing in common
 * beyond the vendor.
 *
 * **SCIM is deliberately absent, and that is not an omission.** Everything here is a
 * service we go to, holding a credential the customer creates for us; SCIM is the
 * opposite — a protocol the customer's own identity provider speaks TO us, against an
 * endpoint and a bearer token WE mint. It has no issuer, no vendor, no client credentials
 * to collect and no third-party documentation to link, because the far end is whatever
 * the customer happens to run. Listing it here would mean inventing a protocol and an
 * empty endpoint set for it just to make the shape fit, and would tell an administrator
 * that "connect SCIM" is the same kind of act as "connect Google" when the fields are
 * ours rather than theirs. It stays a {@see DirectoryProvider} case and nothing more.
 *
 * The dependency runs one way, from here to `Directory`. The catalogue knows which stored
 * provider a directory setup belongs to; the Directory module knows nothing about the
 * catalogue and does not need to, which keeps sync working in a host that never renders a
 * setup screen at all.
 */
class ProviderCatalog
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
            self::linkedin(),
            self::bitbucket(),
            self::xero(),
            self::intuit(),
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

    /**
     * The providers that can be used for one particular thing.
     *
     * A screen asks for the capability it is setting up rather than filtering
     * `all()` itself, so "which providers does the directory page offer" has one answer
     * in one place. The console asking on its own is how the directory page came to offer
     * a different set from the one the product actually supports.
     *
     * @return list<ProviderTemplate>
     */
    public static function withCapability(ProviderCapability $capability): array
    {
        return array_values(array_filter(
            self::all(),
            static fn (ProviderTemplate $t): bool => $t->supports($capability),
        ));
    }

    /**
     * The OTHER direction: setup guides for the enterprise identity providers that sign
     * a customer's people in to us over SAML or OIDC — see {@see IdentityProviderGuides}.
     *
     * Delegated rather than merged, and deliberately not part of {@see self::all()}: an
     * enterprise IdP is not a provider we sign in to, and anything in `all()` can end up
     * as a button on a sign-in page. This is here only so that someone reading the
     * catalogue finds the guides.
     *
     * @return list<IdentityProviderGuide>
     */
    public static function enterpriseGuides(): array
    {
        return IdentityProviderGuides::all();
    }

    /**
     * The catalogue entry behind a stored directory row, or null when there is none.
     *
     * Null is the honest answer for `scim`, which has no entry by design, and it is also
     * the answer a caller gets for any provider whose entry has not been written yet — so
     * callers treat the guide as an enrichment and never as a precondition for reading a
     * directory that already exists.
     */
    public static function forDirectory(DirectoryProvider $provider): ?ProviderTemplate
    {
        foreach (self::all() as $template) {
            if ($template->directory?->provider === $provider) {
                return $template;
            }
        }

        return null;
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
            directory: new DirectorySetup(
                provider: DirectoryProvider::GoogleWorkspace,
                credentials: [
                    new ProviderParameter(
                        key: 'client_email',
                        label: 'Service account email',
                        help: 'From the downloaded JSON key. Ends in .iam.gserviceaccount.com.',
                        example: 'directory-sync@acme-1234.iam.gserviceaccount.com',
                    ),
                    new ProviderParameter(
                        key: 'private_key',
                        label: 'Service account private key',
                        help: 'The `private_key` field of the same JSON key file, newlines and all.',
                        example: "-----BEGIN PRIVATE KEY-----\n…",
                    ),
                    new ProviderParameter(
                        key: 'admin_email',
                        label: 'Admin to impersonate',
                        help: 'The Admin SDK acts as a person, so this must be an account that may read the directory.',
                        example: 'admin@acme.com',
                    ),
                ],
                setupSteps: [
                    'Google Workspace has no SCIM at all, so this is the only way to sync it — and it is not the OAuth client you may already have created for sign-in.',
                    'In the Google Cloud console, open the project and enable the Admin SDK API.',
                    'Create a service account, then create a JSON key for it and download the file. Google gives you the key once.',
                    'Open the service account\'s Details page and copy its Client ID — the long number. Domain-wide delegation is granted to that, not to the email address.',
                    'In the Google ADMIN console (not Cloud) → Security → Access and data control → API controls → Domain-wide delegation, add that client ID with BOTH read-only scopes: .../auth/admin.directory.user.readonly and .../auth/admin.directory.group.readonly. Without the group scope the users arrive and the groups silently do not.',
                    'Paste the JSON key here along with an administrator address for it to impersonate.',
                ],
                documentationUrl: 'https://developers.google.com/workspace/admin/directory/v1/guides/delegation',
            ),
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
            directory: new DirectorySetup(
                provider: DirectoryProvider::MicrosoftEntra,
                credentials: [
                    new ProviderParameter(
                        key: 'tenant_id',
                        label: 'Directory (tenant) ID',
                        help: 'Entra admin centre → Overview. The same GUID the sign-in connection uses.',
                        example: '72f988bf-86f1-41af-91ab-2d7cd011db47',
                    ),
                    new ProviderParameter(
                        key: 'client_id',
                        label: 'Application (client) ID',
                        help: 'From the app registration you granted the Graph permissions to.',
                        example: '9f2c1f7e-0a5b-4a1e-9b3d-6c8f2b7a4d10',
                    ),
                    new ProviderParameter(
                        key: 'client_secret',
                        label: 'Client secret',
                        help: 'The secret VALUE, not its ID. Entra shows it once and it expires on a date you choose.',
                        example: 'Xy8Q~…',
                    ),
                ],
                setupSteps: [
                    'Entra supports SCIM push as well; this is the pull, for organizations that would rather we fetch than configure provisioning.',
                    'In the Entra admin centre, open an app registration — the one you registered for sign-in is fine, it is the same application object.',
                    'Under API permissions, add Microsoft Graph → APPLICATION permissions (not delegated — nobody is signed in when we sync): User.Read.All and Group.Read.All.',
                    'Click "Grant admin consent for <your directory>". Until somebody does, every Graph call is refused and the connection here will fail.',
                    'Under Certificates & secrets, create a client secret and copy its VALUE. Note its expiry — the sync stops on that date.',
                    'Copy the Directory (tenant) ID and Application (client) ID from Overview.',
                ],
                documentationUrl: 'https://learn.microsoft.com/graph/auth-v2-service',
            ),
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

    /**
     * Sign In with LinkedIn using OpenID Connect.
     *
     * The issuer is the one LinkedIn's discovery document names —
     * `https://www.linkedin.com/oauth`, path and all. LinkedIn's own prose still says
     * `https://www.linkedin.com`; the document is what discovery checks against and what
     * the tokens carry, so the document wins.
     *
     * Two things to know. The token endpoint takes the secret in the request BODY only,
     * and the discovery document does not list auth methods at all — which is why silence
     * there keeps the body form rather than switching to Basic. And `sub` is PAIRWISE: the
     * same member has a different subject under each LinkedIn app, so replacing the app
     * on LinkedIn's side unlinks every account here. Keep the app; rotate its secret.
     */
    private static function linkedin(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'linkedin',
            name: 'LinkedIn',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'profile', 'email'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name', emailVerified: 'email_verified'),
            issuerTemplate: 'https://www.linkedin.com/oauth',
            documentationUrl: 'https://learn.microsoft.com/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2',
            setupSteps: [
                'In the LinkedIn Developer Portal, open My apps and select or create your app.',
                'On the Products tab, request "Sign In with LinkedIn using OpenID Connect". Until it is granted, the openid, profile and email scopes are refused.',
                'On the Auth tab, add the redirect URI shown below as a redirect URL. It must be absolute and https, and LinkedIn ignores anything after a "?".',
                'Copy the Client ID and Client Secret from the Auth tab.',
            ],
        );
    }

    /**
     * Bitbucket Cloud, as an OAuth 2.0 consumer.
     *
     * Not OIDC — no discovery, no `id_token` — and unlike the other OAuth 2.0 entries in
     * three ways, each declared rather than special-cased:
     *
     * - **Basic at the token endpoint.** Atlassian documents the exchange with the
     *   consumer key and secret as HTTP Basic credentials and nothing else.
     * - **No address on the profile.** `/2.0/user` carries none; `/2.0/user/emails`
     *   answers Bitbucket's paginated envelope (`values`, `next`), each entry with
     *   `is_primary` and `is_confirmed`. Only the primary address is taken, and only when
     *   it is confirmed — Bitbucket lists unconfirmed addresses too.
     * - **The subject is `uuid`.** Never `username`, which is deprecated, nor
     *   `nickname`, which Atlassian says is not guaranteed to be unique.
     *
     * Scopes live on the consumer, not the request: Bitbucket refuses an authorization
     * asking for a scope the consumer was not granted, so the setup steps say which
     * permissions to tick.
     */
    private static function bitbucket(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'bitbucket',
            name: 'Bitbucket',
            protocol: FederationProtocol::OAuth2,
            scopes: ['account', 'email'],
            profile: new ProviderProfileMap(
                subject: 'uuid',
                email: null,
                name: 'display_name',
                emailVerified: null,
                emailEndpoint: 'https://api.bitbucket.org/2.0/user/emails',
                emailListPath: 'values',
                emailEntryAddress: 'email',
                emailEntryPrimary: 'is_primary',
                emailEntryVerified: 'is_confirmed',
            ),
            authorizationEndpoint: 'https://bitbucket.org/site/oauth2/authorize',
            tokenEndpoint: 'https://bitbucket.org/site/oauth2/access_token',
            profileEndpoint: 'https://api.bitbucket.org/2.0/user',
            documentationUrl: 'https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/',
            setupSteps: [
                'In Bitbucket, open the workspace, then Settings → Workspace settings → OAuth consumers (under Apps and features) → Add consumer.',
                'Give it a Name and set the Callback URL to the redirect URI shown below.',
                'Grant the consumer the Account permissions for email and read. Bitbucket fixes scopes on the consumer and refuses a sign-in that asks for more.',
                'Save, then select the consumer\'s name to reveal its Key and Secret — the key is the client ID.',
            ],
            tokenEndpointAuthMethod: TokenEndpointAuthMethod::ClientSecretBasic,
        );
    }

    /**
     * Sign In with Xero.
     *
     * Plain OIDC with a fixed issuer. Xero's tokens also carry `xero_userid`, the user's
     * id in Xero's own APIs; the account is linked by `sub`, which Xero documents as the
     * unique identifier for the end user and which the `id_token` validation reads.
     * Xero documents `given_name` and `family_name` but no `name` and no
     * `email_verified`, so the address is never carried as verified.
     */
    private static function xero(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'xero',
            name: 'Xero',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'profile', 'email'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email'),
            issuerTemplate: 'https://identity.xero.com',
            documentationUrl: 'https://developer.xero.com/documentation/xero-app-store/app-partner-guides/sign-in/',
            setupSteps: [
                'In the Xero Developer portal, open My Apps and create an app with the "Auth Code" grant type.',
                'Give it a name, a URL, and the redirect URI shown below as its redirect URI.',
                'Save, then generate a client secret and copy it with the client ID — Xero displays the secret once.',
            ],
        );
    }

    /**
     * Sign In with Intuit (QuickBooks), production keys.
     *
     * The issuer is `https://oauth.platform.intuit.com/op/v1`, but Intuit publishes its
     * discovery document at `developer.api.intuit.com` — a document also answers under
     * the issuer, naming a different authorization endpoint from the documented one, so
     * the catalogue pins the documented document.
     *
     * The `id_token` carries no address. Intuit's address, and its camel-cased
     * `emailVerified`, come from UserInfo, so this entry's profile map describes the
     * UserInfo response and the callback reads it after the token is proven. Intuit
     * tells apps to admit people only when `emailVerified` is true; here an unverified
     * address is simply stored unverified, which is the platform's own rule for every
     * provider — nothing merges into an existing account by email.
     *
     * Production only: Intuit's sandbox document differs in its UserInfo host, and
     * Development keys work only against sandbox companies. A sandbox connection is an
     * ordinary hand-configured OIDC connection.
     */
    private static function intuit(): ProviderTemplate
    {
        return new ProviderTemplate(
            key: 'intuit',
            name: 'Intuit',
            protocol: FederationProtocol::Oidc,
            scopes: ['openid', 'email', 'profile'],
            profile: new ProviderProfileMap(subject: 'sub', email: 'email', emailVerified: 'emailVerified'),
            issuerTemplate: 'https://oauth.platform.intuit.com/op/v1',
            documentationUrl: 'https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/openid-connect',
            setupSteps: [
                'Sign in to the Intuit Developer portal and open your app.',
                'Go to the Production section and select Keys & OAuth. Development keys only work against sandbox companies.',
                'Add the redirect URI shown below to the app\'s redirect URIs.',
                'Copy the Client ID and Client secret.',
            ],
            discoveryUrl: 'https://developer.api.intuit.com/.well-known/openid_configuration',
            profileFromUserInfo: true,
        );
    }
}
