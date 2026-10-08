<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Enums\GuideProtocol;
use Cbox\Id\Federation\Enums\GuideReturnKind;
use Cbox\Id\Federation\Enums\SpValue;
use Cbox\Id\Federation\ValueObjects\GuideField;
use Cbox\Id\Federation\ValueObjects\GuideReturns;
use Cbox\Id\Federation\ValueObjects\IdentityProviderGuide;
use Cbox\Id\Federation\ValueObjects\ScimDirectoryGuide;
use Cbox\Id\Federation\ValueObjects\ServiceProviderValues;

/**
 * Step-by-step guides for the enterprise identity providers IT administrators actually
 * run: which screen to open, what to click, and — the part people get wrong — WHICH of
 * our values goes into WHICH of their fields, by the name their admin screen gives it.
 *
 * ## Why this is not {@see ProviderCatalog}
 *
 * The catalogue is the providers WE sign in to with OAuth credentials a customer creates
 * for us — Google, GitHub, Apple — and `ProviderCatalog::withCapability(Login)` is what
 * renders sign-in buttons. This is the opposite direction: a customer's identity
 * provider signing ITS people in to us over SAML 2.0 or OpenID Connect, and pushing them
 * to us over SCIM. Okta is in both, and the two entries share nothing but the name — in
 * the catalogue it is an issuer and a client secret, here it is an "Audience URI (SP
 * Entity ID)" field on an admin screen. An enterprise IdP in the catalogue would put an
 * "Okta" button on every sign-in page, which is exactly what must not happen.
 *
 * ## What an entry is
 *
 * DATA, typed. Each {@see GuideField} names one of our values ({@see SpValue}) and the
 * IdP's label for the field it goes in, verbatim from the vendor's own documentation;
 * the host supplies the values per connection through {@see ServiceProviderValues}. The
 * steps are English; a host that translates its console keeps its own step text and
 * reads the labels from here, because a label is something the administrator looks for
 * on a screen we do not control and must never be translated.
 *
 * ## The rule for adding one
 *
 * Every label was read on the vendor's own documentation, and `documentationUrl` is a
 * page that was actually fetched. A label that could not be verified is left out rather
 * than guessed — a guide that names a field which does not exist is worse than one that
 * names fewer, because the administrator stops trusting the rest of it. For the same
 * reason a SCIM directory guide exists only where the IdP can provision a CUSTOM
 * application over SCIM 2.0 with a bearer token; "it provisions some catalogued apps"
 * does not count, and neither does Basic-only authentication, which our SCIM server
 * does not accept.
 */
class IdentityProviderGuides
{
    /**
     * Every guide, in the order a console offers them: the most common first, the two
     * generic ones last.
     *
     * @return list<IdentityProviderGuide>
     */
    public static function all(): array
    {
        return [
            self::okta(),
            self::entra(),
            self::google(),
            self::onelogin(),
            self::jumpcloud(),
            self::pingfederate(),
            self::pingone(),
            self::adfs(),
            self::auth0(),
            self::keycloak(),
            self::duo(),
            self::cyberark(),
            self::shibboleth(),
            self::oracle(),
            self::sap(),
            self::salesforce(),
            self::lastpass(),
            self::cloudflare(),
            self::genericSaml(),
            self::genericOidc(),
        ];
    }

    public static function find(string $key): ?IdentityProviderGuide
    {
        foreach (self::all() as $guide) {
            if ($guide->key === $key) {
                return $guide;
            }
        }

        return null;
    }

    /** @return list<string> */
    public static function keys(): array
    {
        return array_map(static fn (IdentityProviderGuide $g): string => $g->key, self::all());
    }

    /**
     * The guides for one protocol.
     *
     * @return list<IdentityProviderGuide>
     */
    public static function forProtocol(GuideProtocol $protocol): array
    {
        return array_values(array_filter(self::all(), static fn (IdentityProviderGuide $g): bool => $g->protocol === $protocol));
    }

    /**
     * The guides whose IdP can push people to us over SCIM 2.0 — the directory screen's
     * list. Ask {@see self::genericDirectory()} for the fallback.
     *
     * @return list<IdentityProviderGuide>
     */
    public static function directories(): array
    {
        return array_values(array_filter(self::all(), static fn (IdentityProviderGuide $g): bool => $g->directory !== null));
    }

    /**
     * For an IdP with no guide of its own: any SCIM 2.0 client needs our base URL and a
     * bearer token, and calls them something close to this.
     */
    public static function genericDirectory(): ScimDirectoryGuide
    {
        return new ScimDirectoryGuide(
            fields: [
                new GuideField(SpValue::ScimBaseUrl, 'SCIM base URL'),
                new GuideField(SpValue::ScimToken, 'Authorization: Bearer'),
            ],
            setupSteps: [
                'In your identity provider, add a SCIM 2.0 provisioning target (sometimes called an outbound or push connector).',
                'Enter the SCIM base URL below and use bearer-token (HTTP header) authentication with the token below.',
                'Test the connection, choose which users and groups to push, and turn provisioning on.',
            ],
        );
    }

    private static function okta(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'okta',
            name: 'Okta',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::AcsUrl, 'Single sign-on URL'),
                new GuideField(SpValue::EntityId, 'Audience URI (SP Entity ID)'),
                new GuideField(SpValue::Literal, 'Name ID format', 'EmailAddress'),
                new GuideField(SpValue::Literal, 'Application username format', 'Email'),
                new GuideField(SpValue::SloUrl, 'Single Logout URL', optional: true, location: 'Show Advanced Settings → Enable Single Logout'),
            ],
            returns: new GuideReturns(GuideReturnKind::Url, 'Metadata URL'),
            setupSteps: [
                'In the Okta Admin Console, go to Applications → Applications and click Create App Integration.',
                'Select SAML 2.0 as the Sign-in method and click Next, then name the app and click Next.',
                'Enter the Single sign-on URL and Audience URI (SP Entity ID) below, set Name ID format to EmailAddress and Application username format to Email, and click Next.',
                'Select "This is an internal app that we have created" and click Finish.',
                'Assign the people or groups who should sign in, then copy the Metadata URL from the Sign On tab.',
            ],
            documentationUrl: 'https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'SCIM connector base URL'),
                    new GuideField(SpValue::Literal, 'Unique identifier field for users', 'userName'),
                    new GuideField(SpValue::Literal, 'Authentication Mode', 'HTTP Header'),
                    new GuideField(SpValue::ScimToken, 'Authorization'),
                ],
                setupSteps: [
                    'On the app\'s General tab, click Edit in App Settings, set Provisioning to SCIM and click Save.',
                    'On the Provisioning tab, go to Settings → Integration and click Edit.',
                    'Enter the SCIM connector base URL below and set Unique identifier field for users to userName — it is case-sensitive.',
                    'Choose Push New Users, Push Profile Updates and Push Groups as needed.',
                    'Set Authentication Mode to HTTP Header, paste the token below into Authorization, and save.',
                ],
                documentationUrl: 'https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_scim.htm',
            ),
        );
    }

    private static function entra(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'entra',
            name: 'Microsoft Entra ID',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'Identifier (Entity ID)', location: 'Basic SAML Configuration'),
                new GuideField(SpValue::AcsUrl, 'Reply URL (Assertion Consumer Service URL)', location: 'Basic SAML Configuration'),
                new GuideField(SpValue::Literal, 'Unique User Identifier (Name ID)', 'user.mail', location: 'Attributes & Claims'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'App Federation Metadata Url'),
            setupSteps: [
                'In the Microsoft Entra admin center, go to Enterprise apps → All applications and select New application, then Create your own application.',
                'Name it, select "Integrate any other application you don\'t find in the gallery (Non-gallery)", and create it.',
                'Open Single sign-on, choose SAML, and select Edit in Basic SAML Configuration.',
                'Add the Identifier (Entity ID) and the Reply URL (Assertion Consumer Service URL) below, then save.',
                'In Attributes & Claims, edit Unique User Identifier (Name ID): source attribute user.mail, format Email address.',
                'Assign users or groups, then copy the App Federation Metadata Url from the SAML Certificates section.',
            ],
            documentationUrl: 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'Tenant URL'),
                    new GuideField(SpValue::ScimToken, 'Secret Token'),
                ],
                setupSteps: [
                    'In the same enterprise application, select Provisioning, then New configuration.',
                    'Enter the Tenant URL and Secret Token below.',
                    'Select Test Connection, then Create.',
                    'Assign the users and groups to provision under Users and groups, then select Start provisioning.',
                ],
                documentationUrl: 'https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups',
            ),
        );
    }

    /**
     * Google Workspace has no SCIM for custom apps: its automatic provisioning covers a
     * fixed list of supported apps only. Directory sync for Google is the API pull in
     * {@see ProviderCatalog} (`google` → Directory), not a push.
     */
    private static function google(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'google',
            name: 'Google Workspace',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::AcsUrl, 'ACS URL'),
                new GuideField(SpValue::EntityId, 'Entity ID'),
                new GuideField(SpValue::Literal, 'Name ID format', 'Email'),
                new GuideField(SpValue::Literal, 'Name ID', 'Basic Information > Primary email'),
            ],
            returns: new GuideReturns(GuideReturnKind::Xml, 'Download Metadata'),
            setupSteps: [
                'In the Google Admin console, go to Menu → Apps → Web and mobile apps.',
                'Click Add App → Add custom SAML app, enter a name and click Continue.',
                'Download the IdP metadata on the Google Identity Provider details page, then click Continue.',
                'Enter the ACS URL and Entity ID below, set Name ID format to Email and Name ID to Basic Information > Primary email, and click Continue, then Finish.',
                'Open the app\'s User access, turn it on for the people who should sign in, and save.',
            ],
            documentationUrl: 'https://support.google.com/a/answer/6087519',
        );
    }

    /**
     * OneLogin provisions over SCIM only through its "SCIM Provisioner with SAML"
     * connectors, not the "SAML Custom Connector (Advanced)" the sign-in guide uses — so
     * an organization that wants both starts from the SCIM connector, which carries the
     * same SAML settings, and enables provisioning BEFORE finishing the SAML half.
     */
    private static function onelogin(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'onelogin',
            name: 'OneLogin',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'Audience (EntityID)'),
                new GuideField(SpValue::AcsUrl, 'Recipient'),
                new GuideField(SpValue::AcsUrlPattern, 'ACS (Consumer) URL Validator'),
                new GuideField(SpValue::AcsUrl, 'ACS (Consumer) URL'),
                new GuideField(SpValue::Literal, 'SAML nameID format', 'Email'),
                new GuideField(SpValue::SloUrl, 'Single Logout URL', optional: true),
            ],
            returns: new GuideReturns(GuideReturnKind::Url, 'Issuer URL'),
            setupSteps: [
                'In OneLogin, go to Applications → Applications and click Add App.',
                'Select SAML Custom Connector (Advanced), give it a display name and Save. To provision over SCIM as well, pick SCIM Provisioner with SAML (SCIM v2 Enterprise, full SAML) instead.',
                'On the Configuration tab, enter Audience (EntityID), Recipient, ACS (Consumer) URL Validator and ACS (Consumer) URL below, and set SAML nameID format to Email.',
                'Save, then copy the Issuer URL from the SSO tab.',
                'Assign the app to the people who should sign in.',
            ],
            documentationUrl: 'https://docs.oneidentity.com/bundle/onelogin_app-integration/page/guides/appintegrations/advanced-saml-custom-connector.htm',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'SCIM Base URL', location: 'Configuration → API Connection'),
                    new GuideField(SpValue::ScimToken, 'SCIM Bearer Token', location: 'Configuration → API Connection'),
                ],
                setupSteps: [
                    'Add the app from SCIM Provisioner with SAML (SCIM v2 Enterprise, full SAML) — the SAML Custom Connector cannot provision.',
                    'On the Configuration tab, under API Connection, enter the SCIM Base URL and SCIM Bearer Token below, and Save.',
                    'Click Enable to connect, then on the Provisioning tab select Enable Provisioning and Save.',
                    'Only then complete the SAML settings on the Configuration tab, as in the sign-in guide.',
                ],
                documentationUrl: 'https://docs.oneidentity.com/bundle/onelogin_app-integration/page/guides/appintegrations/creating-scim-custom-connectors.htm',
            ),
        );
    }

    private static function jumpcloud(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'jumpcloud',
            name: 'JumpCloud',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'SP Entity ID'),
                new GuideField(SpValue::AcsUrl, 'ACS URLs'),
                new GuideField(SpValue::Literal, 'SAMLSubject NameID', 'email'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Copy Metadata URL'),
            setupSteps: [
                'In the JumpCloud Admin Portal, go to Access → SSO Applications and click Add New Application.',
                'Choose Custom SAML App, click Next, choose to configure SSO with SAML, enter a Display Label, and click Save Application, then Configure Application.',
                'Enter an IdP Entity ID of your choosing, and the SP Entity ID and ACS URLs below. Leave SAMLSubject NameID as email.',
                'Save, then click Copy Metadata URL (or Export Metadata for the file).',
                'Bind the user groups who should sign in to the application.',
            ],
            documentationUrl: 'https://jumpcloud.com/support/sso-using-custom-saml-application-connectors',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'Base URL', location: 'Provisioning'),
                    new GuideField(SpValue::ScimToken, 'Token', location: 'Provisioning'),
                ],
                setupSteps: [
                    'Open the Custom SAML App and select the Provisioning tab.',
                    'Enter the Base URL and Token below, and a Test User Email that does not yet exist here.',
                    'Click Test Connection.',
                    'Click Activate — not Save; activation is what runs JumpCloud\'s provisioning checks.',
                ],
                documentationUrl: 'https://jumpcloud.com/support/provision-and-manage-users-and-groups-in-apps-using-custom-scim-identity-management-integration',
            ),
        );
    }

    /**
     * PingFederate names two different fields "Endpoint URL" — the ACS on one tab and the
     * logout endpoint on another — so these fields carry their location. Its built-in
     * provisioner cannot take a static bearer token (its "OAuth 2.0 Bearer Token" mode
     * runs a password grant); the SCIM Provisioner add-on can, which is what the
     * directory guide describes.
     */
    private static function pingfederate(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'pingfederate',
            name: 'PingFederate',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'Metadata URL', optional: true, location: 'Import Metadata → URL (add it under Manage Partner Metadata URLs)'),
                new GuideField(SpValue::EntityId, 'Partner’s Entity ID (Connection ID)', location: 'General Info'),
                new GuideField(SpValue::AcsUrl, 'Endpoint URL', location: 'Protocol Settings → Assertion Consumer Service URL (Binding: POST)'),
                new GuideField(SpValue::Literal, 'SAML_SUBJECT', 'mail', location: 'Attribute Contract Fulfillment (Source: Adapter)'),
                new GuideField(SpValue::SloUrl, 'Endpoint URL', optional: true, location: 'Protocol Settings → SLO Service URLs'),
            ],
            returns: new GuideReturns(GuideReturnKind::Xml, 'Metadata Export'),
            setupSteps: [
                'In PingFederate, go to Applications → Integration → SP Connections and click Create Connection.',
                'Choose "Do not use a template for this connection", select Browser SSO Profiles with protocol SAML 2.0, and keep Browser SSO selected.',
                'On Import Metadata, load our metadata URL below — or enter our entity ID in Partner’s Entity ID (Connection ID) by hand.',
                'In Configure Browser SSO, select SP-Initiated SSO, choose Standard identity mapping, and fulfil SAML_SUBJECT from the adapter\'s mail attribute.',
                'In Protocol Settings, add an Assertion Consumer Service URL with Binding POST and our ACS URL as the Endpoint URL.',
                'Choose the signing certificate, activate the connection and save, then export its metadata under System → Protocol Metadata → Metadata Export.',
            ],
            documentationUrl: 'https://docs.pingidentity.com/pingfederate/latest/administrators_reference_guide/pf_accessing_sp_connections.html',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'SCIM URL', location: 'Outbound Provisioning → Target'),
                    new GuideField(SpValue::Literal, 'SCIM Version', '2.0', location: 'Outbound Provisioning → Target'),
                    new GuideField(SpValue::Literal, 'Authentication Methods', 'OAuth 2 Bearer Token', location: 'Outbound Provisioning → Target'),
                    new GuideField(SpValue::ScimToken, 'Access Token', location: 'Outbound Provisioning → Target'),
                ],
                setupSteps: [
                    'Deploy the SCIM Provisioner add-on and choose a Provisioning Data Store — the built-in provisioner cannot use our bearer token.',
                    'Create an SP connection from the SCIM Provisioner template with connection type Outbound Provisioning.',
                    'On the Target screen, enter the SCIM URL below, choose SCIM Version 2.0 and OAuth 2 Bearer Token, and paste the token below into Access Token.',
                    'Map attributes under Manage Channels, then activate the connection and save.',
                ],
                documentationUrl: 'https://docs.pingidentity.com/integrations/scim/pf_scim_connector.html',
            ),
        );
    }

    private static function pingone(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'pingone',
            name: 'PingOne',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'Import from URL', optional: true),
                new GuideField(SpValue::AcsUrl, 'ACS URLs'),
                new GuideField(SpValue::EntityId, 'Entity ID'),
                new GuideField(SpValue::Literal, 'Subject NameID format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', location: 'Configuration'),
                new GuideField(SpValue::SloUrl, 'SLO Endpoint', optional: true, location: 'Configuration'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'IDP Metadata URL'),
            setupSteps: [
                'In the PingOne admin console, go to Applications → Applications and click the + icon.',
                'Enter an Application Name, choose the SAML application type, and click Configure.',
                'Choose Import from URL with our metadata URL below, or Manually Enter the ACS URLs and Entity ID, then Save.',
                'On the Configuration tab, set Subject NameID format to urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress and map Email Address to the subject on Attribute Mappings.',
                'Turn the application on, then copy the IDP Metadata URL from the Overview tab.',
            ],
            documentationUrl: 'https://docs.pingidentity.com/pingone/applications/p1_applications_add_applications.html',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'SCIM Base URL'),
                    new GuideField(SpValue::Literal, 'Authentication Method', 'OAuth 2 Bearer Token'),
                    new GuideField(SpValue::ScimToken, 'OAuth Access Token'),
                    new GuideField(SpValue::Literal, 'Auth Type Header', 'Bearer'),
                ],
                setupSteps: [
                    'Go to Integrations → Provisioning, click + and New Connection, then select Identity Store and the SCIM Outbound tile.',
                    'Enter the SCIM Base URL below, set Authentication Method to OAuth 2 Bearer Token, paste the token below into OAuth Access Token, set Auth Type Header to Bearer, and click Test connection.',
                    'Choose the user actions to allow, save, and turn the connection on.',
                    'Click + and New Rule, choose PingOne as Source, select this connection and set the user filter and groups.',
                ],
                documentationUrl: 'https://docs.pingidentity.com/pingone/integrations/p1_create_scim_connection.html',
            ),
        );
    }

    /**
     * AD FS. No SCIM: AD FS federates and does not provision. The metadata import is the
     * recommended path because it brings our certificate and endpoints together; the
     * manual fields are for an AD FS that cannot reach us.
     */
    private static function adfs(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'adfs',
            name: 'AD FS',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'Federation metadata address (host name or URL)', location: 'Select Data Source'),
                new GuideField(SpValue::AcsUrl, 'Relying party SAML 2.0 SSO service URL', location: 'Configure URL'),
                new GuideField(SpValue::EntityId, 'Relying party identifier', location: 'Configure Identifiers'),
                new GuideField(SpValue::Literal, 'Outgoing claim type', 'Name ID', location: 'Transform an Incoming Claim (from E-Mail Address)'),
            ],
            returns: new GuideReturns(GuideReturnKind::Url, 'https://<adfs-host>/federationmetadata/2007-06/federationmetadata.xml'),
            setupSteps: [
                'In AD FS Management, under Actions, click Add Relying Party Trust, choose Claims aware, and click Start.',
                'Choose "Import data about the relying party published online or on a local network" and enter our metadata URL below — or enter the data manually.',
                'Entering it manually: select "Enable support for the SAML 2.0 WebSSO protocol" and enter our ACS URL, then add our entity ID as an identifier.',
                'Choose an access control policy and finish the wizard.',
                'In Edit Claim Issuance Policy, add a Send LDAP Attributes as Claims rule (E-Mail-Addresses → E-Mail Address) and a Transform an Incoming Claim rule (E-Mail Address → Name ID).',
                'Send us your federation metadata URL: https://<adfs-host>/federationmetadata/2007-06/federationmetadata.xml.',
            ],
            documentationUrl: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/create-a-relying-party-trust',
        );
    }

    /**
     * Auth0 as an identity provider, through its SAML2 Web App addon. The addon signs
     * with SHA-1 unless told otherwise, so the guide sets SHA-256 explicitly. The JSON
     * keys are the addon's settings keys, which is what its Settings tab shows.
     */
    private static function auth0(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'auth0',
            name: 'Auth0',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::AcsUrl, 'Application Callback URL', location: 'Addons → SAML2 Web App → Settings'),
                new GuideField(SpValue::EntityId, 'audience', location: 'Addons → SAML2 Web App → Settings (JSON)'),
                new GuideField(SpValue::Literal, 'nameIdentifierFormat', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', location: 'Addons → SAML2 Web App → Settings (JSON)'),
                new GuideField(SpValue::Literal, 'signatureAlgorithm', 'rsa-sha256', location: 'Addons → SAML2 Web App → Settings (JSON)'),
                new GuideField(SpValue::Literal, 'digestAlgorithm', 'sha256', location: 'Addons → SAML2 Web App → Settings (JSON)'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Identity Provider Metadata'),
            setupSteps: [
                'In the Auth0 Dashboard, go to Applications → Applications and create or open the application for this service.',
                'On the Addons tab, turn on SAML2 Web App.',
                'On its Settings tab, enter our ACS URL as the Application Callback URL.',
                'In the settings JSON, set audience to our entity ID, nameIdentifierFormat to the email address format, signatureAlgorithm to rsa-sha256 and digestAlgorithm to sha256 — Auth0 signs with SHA-1 otherwise.',
                'Save, then on the Usage tab download the Identity Provider Metadata (or copy https://<your-domain>/samlp/metadata/<client-id>).',
            ],
            documentationUrl: 'https://auth0.com/docs/authenticate/protocols/saml/saml-sso-integrations/configure-auth0-saml-identity-provider',
        );
    }

    /**
     * Keycloak, over OpenID Connect — the protocol its own documentation recommends "for
     * most purposes". Keycloak's SCIM support is a SCIM SERVER (people pushed INTO
     * Keycloak), not provisioning out of it, so there is no directory guide.
     */
    private static function keycloak(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'keycloak',
            name: 'Keycloak',
            protocol: GuideProtocol::Oidc,
            fields: [
                new GuideField(SpValue::RedirectUri, 'Valid Redirect URIs'),
                new GuideField(SpValue::Literal, 'Client authentication', 'On', location: 'Capability config'),
                new GuideField(SpValue::Literal, 'Scopes', 'openid email profile'),
            ],
            returns: new GuideReturns(GuideReturnKind::Oidc, 'https://<host>/realms/<realm>, Client ID, Client Secret (Credentials tab)'),
            setupSteps: [
                'In the Keycloak admin console, select your realm — not master — then Clients → Create client.',
                'Leave Client type as OpenID Connect and enter a Client ID.',
                'Turn Client authentication on and keep Standard flow enabled — a public client has no secret to give us.',
                'Add the redirect URI below to Valid Redirect URIs. Avoid wildcards.',
                'Copy the client secret from the Credentials tab; the issuer is https://<host>/realms/<realm>.',
            ],
            documentationUrl: 'https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc_clients',
        );
    }

    private static function duo(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'duo',
            name: 'Duo',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'Metadata XML URL', optional: true, location: 'Service Provider → Metadata Discovery'),
                new GuideField(SpValue::EntityId, 'Entity ID', location: 'Service Provider'),
                new GuideField(SpValue::AcsUrl, 'Assertion Consumer Service (ACS) URL', location: 'Service Provider'),
                new GuideField(SpValue::SloUrl, 'Single Logout URL', optional: true, location: 'Service Provider'),
                new GuideField(SpValue::LoginUrl, 'Service Provider Login URL', optional: true, location: 'Service Provider'),
                new GuideField(SpValue::Literal, 'NameID attribute', '<Email Address>', location: 'SAML Response'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Metadata URL'),
            setupSteps: [
                'In the Duo Admin Panel, go to Applications → Application Catalog, find Generic SAML Service Provider (SSO), and click Add.',
                'Under User access, choose the groups who may sign in.',
                'In Service Provider, enter the Entity ID and Assertion Consumer Service (ACS) URL below — or choose Metadata XML URL under Metadata Discovery, enter ours and click Populate.',
                'In SAML Response, set NameID attribute to <Email Address>.',
                'Save, then copy the Metadata URL from the Metadata section.',
            ],
            documentationUrl: 'https://duo.com/docs/sso-generic',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::Literal, 'Authentication', 'Bearer Token', location: 'Provisioning'),
                    new GuideField(SpValue::ScimBaseUrl, 'Base URL', location: 'Provisioning'),
                    new GuideField(SpValue::ScimToken, 'Token', location: 'Provisioning'),
                ],
                setupSteps: [
                    'Open the application under Applications → Applications and select the Provisioning tab.',
                    'Under Authentication, choose Bearer Token and enter the Base URL and Token below.',
                    'Click Connect to application and wait for it to succeed.',
                    'Review the attribute mappings and choose the groups to provision.',
                    'Click Save and enable.',
                ],
                documentationUrl: 'https://duo.com/docs/automated-provisioning',
            ),
        );
    }

    /**
     * CyberArk Identity (its documentation now calls the product Idira Identity). The SP
     * entity ID label is printed with that spacing in CyberArk's own field reference.
     */
    private static function cyberark(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'cyberark',
            name: 'CyberArk Identity',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'Metadata', optional: true, location: 'Trust → Service Provider Configuration (URL, then Load)'),
                new GuideField(SpValue::EntityId, 'SP Entity ID/ Issuer /Audience', location: 'Trust → Service Provider Configuration → Manual Configuration'),
                new GuideField(SpValue::AcsUrl, 'Assertion Consumer Service (ACS) URL', location: 'Trust → Service Provider Configuration → Manual Configuration'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Copy URL'),
            setupSteps: [
                'In the Identity Administration portal, click Apps, then Add Web Apps, and on the Custom tab click Add next to SAML.',
                'Enter a Name and Description on the Settings page.',
                'On the Trust page, under Service Provider Configuration, load our metadata URL — or choose Manual Configuration and enter the SP Entity ID/ Issuer /Audience and Assertion Consumer Service (ACS) URL below.',
                'Save, then under Identity Provider Configuration click Copy URL for the metadata (or Download Metadata File).',
                'Configure the attributes on the SAML Response page and assign the people who should sign in.',
            ],
            documentationUrl: 'https://docs.cyberark.com/manage/latest/en/content/identity/applications/appscustom/addconfigsaml.htm',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimBaseUrl, 'SCIM Service URL', location: 'Provisioning'),
                    new GuideField(SpValue::Literal, 'Authorization Type', 'Authorization Header', location: 'Provisioning'),
                    new GuideField(SpValue::Literal, 'Header Type', 'Bearer Token', location: 'Provisioning'),
                    new GuideField(SpValue::ScimToken, 'Bearer Token', location: 'Provisioning'),
                ],
                setupSteps: [
                    'Open the custom SAML app\'s Provisioning tab and select "Enable provisioning for this application", in Live Mode.',
                    'Enter the SCIM Service URL below.',
                    'Set Authorization Type to Authorization Header and Header Type to Bearer Token, and paste the token below into Bearer Token.',
                    'Click Verify, then choose the roles to provision.',
                ],
                documentationUrl: 'https://docs.cyberark.com/manage/latest/en/content/identity/applications/appscustom/configsaml_adminautoprov.htm',
            ),
        );
    }

    /**
     * The Shibboleth IdP has no admin screen: it is configured in files, so the "labels"
     * are the configuration elements the administrator edits. Our metadata URL carries
     * the ACS and entity ID, which is why that is the one value asked for.
     */
    private static function shibboleth(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'shibboleth',
            name: 'Shibboleth',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'metadataURL', location: 'conf/metadata-providers.xml → <MetadataProvider xsi:type="FileBackedHTTPMetadataProvider">'),
                new GuideField(SpValue::EntityId, 'value', location: 'conf/attribute-filter.xml → <PolicyRequirementRule xsi:type="Requester">'),
                new GuideField(SpValue::Literal, 'nameIDFormatPrecedence', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', location: 'conf/relying-party.xml → SAML2.SSO'),
            ],
            returns: new GuideReturns(GuideReturnKind::Xml, 'idp-metadata.xml'),
            setupSteps: [
                'In conf/metadata-providers.xml, add a FileBackedHTTPMetadataProvider whose metadataURL is our metadata URL below, with a backingFile.',
                'In conf/attribute-filter.xml, add an AttributeFilterPolicy whose Requester rule names our entity ID and that releases mail (and the name attributes).',
                'In conf/saml-nameid.xml, add a SAML2AttributeSourcedGenerator for the emailAddress format sourced from mail.',
                'In conf/relying-party.xml, add a RelyingPartyByName override for our entity ID setting nameIDFormatPrecedence to the emailAddress format.',
                'Send us your IdP metadata (metadata/idp-metadata.xml as you publish it).',
            ],
            documentationUrl: 'https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199506865/FileBackedHTTPMetadataProvider',
        );
    }

    /**
     * OCI IAM identity domains (formerly IDCS). Its SCIM template asks for our base URL
     * in two halves — "Host Name" and "Base URI" — which is why those exist as values.
     */
    private static function oracle(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'oracle',
            name: 'Oracle Cloud Infrastructure IAM',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'Entity ID', location: 'Configure single sign-on → General'),
                new GuideField(SpValue::AcsUrl, 'Assertion consumer URL', location: 'Configure single sign-on → General'),
                new GuideField(SpValue::Literal, 'Name ID value', 'Primary email address', location: 'Configure single sign-on → General'),
                new GuideField(SpValue::SloUrl, 'Single logout URL', optional: true, location: 'Configure single sign-on → Additional configurations'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Download identity provider metadata'),
            setupSteps: [
                'In the identity domain, select Integrated applications, then Add application, choose SAML Application and select Launch workflow.',
                'Enter a Name and select Next.',
                'In Configure single sign-on, enter the Entity ID and Assertion consumer URL below and set Name ID value to Primary email address, then select Finish.',
                'Activate the application and assign the users or groups who should sign in.',
                'Select Download identity provider metadata — or, with Configure client access enabled under Access signing certificate, give us https://<domain-url>/fed/v1/metadata.',
            ],
            documentationUrl: 'https://docs.oracle.com/en-us/iaas/Content/Identity/applications/add-saml-application.htm',
            directory: new ScimDirectoryGuide(
                fields: [
                    new GuideField(SpValue::ScimHost, 'Host Name', location: 'Configure connectivity'),
                    new GuideField(SpValue::ScimBasePath, 'Base URI', location: 'Configure connectivity'),
                    new GuideField(SpValue::ScimToken, 'Access Token', location: 'Configure connectivity'),
                ],
                setupSteps: [
                    'In Integrated applications, select Add application, then Application Catalog, and launch the app catalog.',
                    'Under Types of integration choose Provisioning, and pick GenericScim - Bearer Token.',
                    'Name it and select Next.',
                    'In Configure connectivity, enter the Host Name, Base URI and Access Token below — Oracle asks for our SCIM URL in two halves.',
                    'Select Test connectivity and confirm the connection succeeds.',
                ],
                documentationUrl: 'https://docs.oracle.com/en-us/iaas/Content/Identity/scim/add-application-using-generic-scim-app-template.htm',
            ),
        );
    }

    /**
     * SAP Cloud Identity Services – Identity Authentication. SAP recommends loading the
     * service provider's metadata from its URL — that is also what keeps certificate
     * renewal automatic — so that is the value asked for. Its Identity Provisioning SCIM
     * target authenticates with Basic or OAuth client credentials only, never a static
     * bearer token, so there is no directory guide.
     */
    private static function sap(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'sap',
            name: 'SAP Cloud Identity Services',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::SpMetadataUrl, 'Load from URL', location: 'Trust → SINGLE SIGN-ON → SAML 2.0 Configuration'),
                new GuideField(SpValue::Literal, 'Subject Name Identifier', 'Email', location: 'Trust → SINGLE SIGN-ON'),
                new GuideField(SpValue::Literal, 'Default Name ID Format', 'Email', location: 'Trust → SINGLE SIGN-ON'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Download Metadata File'),
            setupSteps: [
                'In the administration console for SAP Cloud Identity Services, under Applications and Resources, choose the Applications tile and choose Create.',
                'Enter a Display Name, select SAML 2.0 as the Protocol Type, and save.',
                'On the Trust tab, under SINGLE SIGN-ON, choose SAML 2.0 Configuration and use Load from URL with our metadata URL below.',
                'Set Subject Name Identifier to Email and Default Name ID Format to Email.',
                'Under Tenant Settings → SAML 2.0 Configuration, choose Download Metadata File — or give us https://<tenant-id>.accounts.ondemand.com/saml2/metadata.',
            ],
            documentationUrl: 'https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/configure-saml-2-0-service-provider',
        );
    }

    /**
     * Salesforce as an identity provider. New connected apps can no longer be created
     * freely, so the SAML settings live on an External Client App. Salesforce has no
     * generic outbound SCIM; its user provisioning runs flows and Apex.
     */
    private static function salesforce(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'salesforce',
            name: 'Salesforce',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'Entity ID', location: 'Web App (Enable SAML Settings)'),
                new GuideField(SpValue::AcsUrl, 'ACS URL', location: 'Web App (Enable SAML Settings)'),
                new GuideField(SpValue::Literal, 'Name ID Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', location: 'Web App (Enable SAML Settings)'),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'Download Metadata'),
            setupSteps: [
                'From Setup, enter Identity Provider in the Quick Find box, click Enable Identity Provider, choose a certificate and save.',
                'From App Manager, create a New External Client App with a Local distribution state.',
                'In Web App (Enable SAML Settings), select Enable SAML and enter the Entity ID and ACS URL below.',
                'Set Subject Type (for example Username) and the Name ID Format to the email address format, and save.',
                'Give users access through profiles or permission sets, then on the Identity Provider page click Download Metadata.',
            ],
            documentationUrl: 'https://help.salesforce.com/s/articleView?id=xcloud.configure_external_client_app_saml.htm&type=5',
        );
    }

    private static function lastpass(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'lastpass',
            name: 'LastPass',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::AcsUrl, 'Assertion Consumer Service'),
                new GuideField(SpValue::EntityId, 'Service Provider entity ID'),
                new GuideField(SpValue::LoginUrl, 'Launch URL', optional: true),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'SAML IdP Metadata'),
            setupSteps: [
                'In the LastPass Admin Console, go to Applications → SSO apps and select Add app.',
                'Select Custom Service, then Add new domain.',
                'Choose the groups and additional users that have access to this service.',
                'Enter the Assertion Consumer Service and Service Provider entity ID below, and select Save.',
                'Turn on "Service is enabled", save, and copy the SAML IdP Metadata.',
            ],
            documentationUrl: 'https://support.lastpass.com/s/document-item?language=en_US&bundleId=lastpass&topicId=LastPass/uac_applications_sso_apps.html&_LANG=enus',
        );
    }

    /**
     * Cloudflare Access acting as the identity provider for a SaaS application ("Access
     * for SaaS"). Its SCIM passthrough to SaaS apps is an API-only closed beta, so there
     * is no directory guide.
     */
    private static function cloudflare(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'cloudflare',
            name: 'Cloudflare Access',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'Entity ID'),
                new GuideField(SpValue::AcsUrl, 'Assertion Consumer Service URL'),
                new GuideField(SpValue::Literal, 'Name ID Format', 'Email'),
            ],
            returns: new GuideReturns(GuideReturnKind::Url, 'SSO endpoint'),
            setupSteps: [
                'In Cloudflare Zero Trust, go to Access controls → Applications, select Create new application, then SaaS application.',
                'Type a custom name in the Application field, select SAML, and add the application.',
                'Enter the Entity ID and Assertion Consumer Service URL below, and set Name ID Format to Email.',
                'Copy the SSO endpoint — its metadata is at <SSO endpoint>/saml-metadata.',
                'Add an Allow policy, choose the identity providers, and create the application.',
            ],
            documentationUrl: 'https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/saas-apps/generic-saml-saas/',
        );
    }

    private static function genericSaml(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'saml',
            name: 'SAML 2.0',
            protocol: GuideProtocol::Saml,
            fields: [
                new GuideField(SpValue::EntityId, 'SP Entity ID / Audience'),
                new GuideField(SpValue::AcsUrl, 'ACS URL / Reply URL'),
                new GuideField(SpValue::Literal, 'NameID format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
                new GuideField(SpValue::SpMetadataUrl, 'SP metadata URL', optional: true),
                new GuideField(SpValue::SloUrl, 'Single Logout URL', optional: true),
            ],
            returns: new GuideReturns(GuideReturnKind::UrlOrXml, 'IdP metadata'),
            setupSteps: [
                'In your identity provider, create a new SAML 2.0 application (sometimes called a service provider or relying party).',
                'Import our metadata URL below if it can, or enter the entity ID and ACS URL by hand.',
                'Send the person\'s email address as the NameID, in the emailAddress format.',
                'Assign the people who should sign in, then give us the IdP metadata — a URL if there is one, otherwise the XML file.',
            ],
        );
    }

    private static function genericOidc(): IdentityProviderGuide
    {
        return new IdentityProviderGuide(
            key: 'oidc',
            name: 'OpenID Connect',
            protocol: GuideProtocol::Oidc,
            fields: [
                new GuideField(SpValue::RedirectUri, 'Redirect URI / Callback URL'),
                new GuideField(SpValue::Literal, 'Scopes', 'openid email profile'),
            ],
            returns: new GuideReturns(GuideReturnKind::Oidc, 'Issuer URL, Client ID, Client secret'),
            setupSteps: [
                'In your identity provider, create a confidential web application (authorization code flow) — one that issues a client secret.',
                'Add the redirect URI below exactly, and allow the openid, email and profile scopes.',
                'Give us the issuer URL, the client ID and the client secret. We read everything else from the issuer\'s discovery document.',
            ],
        );
    }
}
