<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris;

use Cbox\Id\Directory\Connectors\BambooHrConnector;
use Cbox\Id\Directory\Connectors\WorkdayConnector;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\IncompleteHrisCredentials;
use Cbox\Id\Directory\Hris\ValueObjects\HrisCredential;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSetup;

/**
 * The HR systems an organization can sync its people from, and how to connect each one:
 * what to create on their side, what to paste on ours, where their documentation is.
 *
 * Static data, like the federation catalogue, and checked the same way: every credential
 * listed here is one the connector reads, and every one the connector demands is listed
 * (`HrisCatalogTest` drives the real connectors with the declared set). A form built from
 * this catalogue therefore collects exactly what the sync will use.
 *
 * Kept apart from `Cbox\Id\Federation\ProviderCatalog` because an HR system is never a
 * sign-in provider, and anything in that catalogue can end up as a button on a sign-in page.
 *
 * The setup steps are English and current as the vendors' own documentation described them
 * when written; a host that shows them translated keys its translations by
 * {@see HrisSetup::$provider}.
 */
final class HrisCatalog
{
    /**
     * @return list<HrisSetup>
     */
    public static function all(): array
    {
        return [
            self::workday(),
            self::bambooHr(),
            self::rippling(),
            self::hiBob(),
            self::personio(),
        ];
    }

    public static function for(DirectoryProvider $provider): ?HrisSetup
    {
        foreach (self::all() as $setup) {
            if ($setup->provider === $provider) {
                return $setup;
            }
        }

        return null;
    }

    /**
     * Every credential key any HR system reads — the shape of a "credentials" object that
     * can hold any of them.
     *
     * @return list<string>
     */
    public static function credentialKeys(): array
    {
        $keys = [];

        foreach (self::all() as $setup) {
            foreach ($setup->credentialKeys() as $key) {
                $keys[$key] = true;
            }
        }

        return array_keys($keys);
    }

    /**
     * The fields a Workday report's column names can be overridden for
     * ({@see WorkdayConnector::COLUMNS}), with the default column for each.
     *
     * @return array<string, string>
     */
    public static function fieldMapDefaults(): array
    {
        return WorkdayConnector::COLUMNS;
    }

    /**
     * The credentials for one HR system, trimmed, limited to the keys it reads, normalised
     * (a pasted BambooHR address becomes its subdomain; a Workday report address is pinned
     * to Workday's hosts) — or the refusal that names what is missing or wrong.
     *
     * @param  array<mixed>  $given
     * @return array<string, string>
     *
     * @throws IncompleteHrisCredentials
     */
    public static function credentialsFrom(DirectoryProvider $provider, array $given): array
    {
        $setup = self::for($provider) ?? throw IncompleteHrisCredentials::invalid($provider->label(), 'provider', 'This is not an HR system.');

        $values = [];

        foreach ($setup->credentialKeys() as $key) {
            $value = $given[$key] ?? null;

            if (is_string($value) && trim($value) !== '') {
                $values[$key] = trim($value);
            }
        }

        $missing = array_values(array_diff($setup->requiredCredentialKeys(), array_keys($values)));

        if ($missing !== []) {
            throw IncompleteHrisCredentials::missing($setup->name, $missing);
        }

        return match ($provider) {
            DirectoryProvider::Workday => self::workdayCredentials($values),
            DirectoryProvider::BambooHr => ['subdomain' => BambooHrConnector::subdomain($values['subdomain'])] + $values,
            default => $values,
        };
    }

    /**
     * @param  array<string, string>  $values
     * @return array<string, string>
     */
    private static function workdayCredentials(array $values): array
    {
        $values['report_url'] = WorkdayConnector::reportAddress($values['report_url'])['url'];

        $oauth = array_intersect_key($values, array_flip(['client_id', 'client_secret', 'refresh_token']));
        $isu = array_intersect_key($values, array_flip(['username', 'password']));

        if (count($oauth) === 3) {
            return ['report_url' => $values['report_url']] + $oauth;
        }

        if (count($isu) === 2) {
            return ['report_url' => $values['report_url']] + $isu;
        }

        throw new IncompleteHrisCredentials(
            'Workday needs either the integration system user\'s username and password, or an API client\'s client ID, client secret and refresh token.',
            count($oauth) > 0 ? array_values(array_diff(['client_id', 'client_secret', 'refresh_token'], array_keys($oauth))) : array_values(array_diff(['username', 'password'], array_keys($isu))),
        );
    }

    private static function workday(): HrisSetup
    {
        return new HrisSetup(
            provider: DirectoryProvider::Workday,
            name: 'Workday',
            credentials: [
                new HrisCredential('report_url', 'Report web-service URL', 'The JSON URL from the report\'s related actions → Web Service → View URLs.', 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU_CboxID/Cbox_ID_Workers?format=json'),
                new HrisCredential('username', 'Integration system user', 'The ISU\'s user name followed by @ and your tenant name. Leave empty when you use an API client instead.', 'ISU_CboxID@acme', required: false),
                new HrisCredential('password', 'Integration system user password', 'The ISU\'s password.', '', secret: true, required: false),
                new HrisCredential('client_id', 'API client ID', 'Only when you use an API client instead of a user name and password.', '', required: false),
                new HrisCredential('client_secret', 'API client secret', 'The secret shown when the API client was registered.', '', secret: true, required: false),
                new HrisCredential('refresh_token', 'Refresh token', 'From Manage Refresh Tokens for Integrations, issued to the integration system user.', '', secret: true, required: false),
            ],
            setupSteps: [
                'Run the task Create Integration System User. Give it a name such as ISU_CboxID and a strong password, and tick "Do Not Allow UI Sessions".',
                'Run Create Security Group, choose "Integration System Security Group (Unconstrained)", and add the user. In Maintain Permissions for Security Group, give it Get access to the Worker Data domains your report reads (workers, work email, job details, supervisory organizations), then run Activate Pending Security Policy Changes.',
                'Create an Advanced custom report on the All Workers data source (so it includes terminated workers), tick "Enable As Web Service", and share it with the integration user.',
                'Add one column per field and set each column\'s alias to exactly: Employee_ID, Work_Email, Legal_First_Name, Legal_Last_Name, Preferred_Name, Active_Status, On_Leave, Hire_Date, Termination_Date, Supervisory_Organization_ID, Supervisory_Organization, Manager_Employee_ID, Business_Title. Only Employee_ID and Work_Email are required; a report that already exists can keep its own names and map them here.',
                'From the report\'s related actions choose Web Service → View URLs, and copy the JSON URL.',
                'Paste the URL, the user name as ISU_CboxID@your-tenant, and its password. To use OAuth instead, run Register API Client for Integrations with non-expiring refresh tokens, then Manage Refresh Tokens for Integrations for the integration user, and paste the client ID, secret and refresh token.',
            ],
            documentationUrl: 'https://doc.workday.com/admin-guide/en-us/reporting-and-analytics/custom-reports-and-analytics/reports-as-a-service-raas-/dan1370797813643.html',
        );
    }

    private static function bambooHr(): HrisSetup
    {
        return new HrisSetup(
            provider: DirectoryProvider::BambooHr,
            name: 'BambooHR',
            credentials: [
                new HrisCredential('subdomain', 'Company subdomain', 'The part before .bamboohr.com in the address you sign in at.', 'acme'),
                new HrisCredential('api_key', 'API key', 'Created by the integration user under their profile → API Keys. Shown once.', '', secret: true),
            ],
            setupSteps: [
                'Create a dedicated BambooHR user for the integration, with an access level that can see every employee — active and inactive — and their work email, job, department, supervisor, hire and termination dates.',
                'Sign in as that user, open the account menu (your name, top right) → API Keys, and choose Add New Key. Name it "Cbox ID" and copy the key; it is shown once.',
                'Paste the key and your company subdomain: the part before .bamboohr.com in the address you sign in at.',
            ],
            documentationUrl: 'https://documentation.bamboohr.com/docs/getting-started',
            incremental: true,
        );
    }

    private static function rippling(): HrisSetup
    {
        return new HrisSetup(
            provider: DirectoryProvider::Rippling,
            name: 'Rippling',
            credentials: [
                new HrisCredential('api_token', 'API token', 'Created under Tools → Developer → API Tokens. Shown once.', '', secret: true),
            ],
            setupSteps: [
                'Sign in as an administrator whose permission profile covers the entire company — the token sees exactly what its creator sees. A dedicated service administrator is best: Rippling revokes a token when its creator leaves.',
                'Go to Tools → Developer → API Tokens and choose Create API token. Name it "Cbox ID".',
                'Grant the read scopes workers.read, users.read and departments.read, and nothing else.',
                'Copy the token and paste it here. Rippling also revokes a token that goes unused for 30 days, which a scheduled sync never lets happen.',
            ],
            documentationUrl: 'https://developer.rippling.com/documentation/rest-api/essentials/api-tokens',
            incremental: true,
        );
    }

    private static function hiBob(): HrisSetup
    {
        return new HrisSetup(
            provider: DirectoryProvider::HiBob,
            name: 'HiBob',
            credentials: [
                new HrisCredential('service_user_id', 'Service user ID', 'Shown when the API service user is created.', 'SERVICE-12345'),
                new HrisCredential('service_user_token', 'Service user token', 'Shown once, when the API service user is created.', '', secret: true),
            ],
            setupSteps: [
                'In Bob, go to Settings → Integrations → Service users, and create a service user named "Cbox ID". Copy its ID and token; the token is shown once.',
                'Create a permission group for it. Under People\'s data, give View access to the Basic info, Work and Lifecycle (internal) categories.',
                'Set the group\'s "Access data for" to everybody, including people who are no longer employed — otherwise leavers never reach us and are never deprovisioned.',
                'Add the service user to that group, then paste its ID and token here.',
            ],
            documentationUrl: 'https://apidocs.hibob.com/docs/how-to-read-employee-data',
        );
    }

    private static function personio(): HrisSetup
    {
        return new HrisSetup(
            provider: DirectoryProvider::Personio,
            name: 'Personio',
            credentials: [
                new HrisCredential('client_id', 'Client ID', 'From Settings → Integrations → API credentials.', 'papi-…'),
                new HrisCredential('client_secret', 'Client secret', 'Shown once, when the credentials are generated.', '', secret: true),
            ],
            setupSteps: [
                'In Personio, go to Settings → Integrations → API credentials and choose Generate new credentials. Name them "Cbox ID".',
                'Grant read access to persons and to org units (personio:persons:read, personio:org-units:read), and nothing that writes.',
                'Copy the client ID and client secret — the secret is shown once — and paste them here.',
            ],
            documentationUrl: 'https://developer.personio.de/reference/authentication',
        );
    }
}
