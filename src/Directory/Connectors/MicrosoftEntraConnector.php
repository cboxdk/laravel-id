<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Connectors;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\ValueObjects\DirectoryGroupSnapshot;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Illuminate\Support\Facades\Http;

/**
 * Pulls users from Microsoft Entra ID via the Microsoft Graph API, authenticated
 * with the app registration's client credentials (no user in the loop). Credentials:
 * `tenant_id`, `client_id`, `client_secret`. The app needs the `User.Read.All`
 * application permission (admin-consented). Deactivated Entra accounts
 * (`accountEnabled=false`) arrive as inactive users, so the reconciliation
 * deprovisions them downstream.
 */
class MicrosoftEntraConnector implements DirectoryConnector
{
    private const GRAPH = 'https://graph.microsoft.com/v1.0';

    private const SELECT = 'id,userPrincipalName,displayName,mail,accountEnabled';

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::MicrosoftEntra;
    }

    public function fetchUsers(array $credentials): iterable
    {
        $token = $this->accessToken($credentials);
        $url = self::GRAPH.'/users?$select='.self::SELECT.'&$top=999';

        // Follow Graph's @odata.nextLink pagination to completion.
        while ($url !== null) {
            $response = Http::withToken($token)->acceptJson()->get($url);

            if ($response->failed()) {
                throw DirectoryConnectionFailed::make('Microsoft Entra', 'Graph users request failed ('.$response->status().').');
            }

            $body = $response->json();
            $body = is_array($body) ? $body : [];

            /** @var array<int, array<string, mixed>> $users */
            $users = is_array($body['value'] ?? null) ? $body['value'] : [];

            foreach ($users as $user) {
                $scim = $this->toScimUser($user);

                if ($scim !== null) {
                    yield $scim;
                }
            }

            // The pagination key is the LITERAL string '@odata.nextLink' — read it
            // directly, not via dot-path lookup (the '.' is part of the key name).
            $next = $body['@odata.nextLink'] ?? null;
            $url = is_string($next) && $next !== '' ? $next : null;
        }
    }

    public function fetchGroups(array $credentials): iterable
    {
        $token = $this->accessToken($credentials);
        $url = self::GRAPH.'/groups?$select=id,displayName&$top=999';

        while ($url !== null) {
            $response = Http::withToken($token)->acceptJson()->get($url);

            if ($response->failed()) {
                throw DirectoryConnectionFailed::make('Microsoft Entra', 'Graph groups request failed ('.$response->status().').');
            }

            $body = is_array($response->json()) ? $response->json() : [];
            /** @var array<int, array<string, mixed>> $groups */
            $groups = is_array($body['value'] ?? null) ? $body['value'] : [];

            foreach ($groups as $group) {
                $id = $group['id'] ?? null;
                $name = $group['displayName'] ?? null;

                if (is_string($id) && $id !== '' && is_string($name) && $name !== '') {
                    yield new DirectoryGroupSnapshot($id, $name, $this->groupMembers($token, $id));
                }
            }

            $next = $body['@odata.nextLink'] ?? null;
            $url = is_string($next) && $next !== '' ? $next : null;
        }
    }

    /**
     * @return list<string>
     */
    private function groupMembers(string $token, string $groupId): array
    {
        // The /microsoft.graph.user OData cast returns only user members.
        $url = self::GRAPH.'/groups/'.$groupId.'/members/microsoft.graph.user?$select=id&$top=999';
        $ids = [];

        while ($url !== null) {
            $response = Http::withToken($token)->acceptJson()->get($url);

            if ($response->failed()) {
                break;
            }

            $body = is_array($response->json()) ? $response->json() : [];

            foreach ((is_array($body['value'] ?? null) ? $body['value'] : []) as $member) {
                if (is_array($member) && is_string($member['id'] ?? null)) {
                    $ids[] = $member['id'];
                }
            }

            $next = $body['@odata.nextLink'] ?? null;
            $url = is_string($next) && $next !== '' ? $next : null;
        }

        return $ids;
    }

    public function verify(array $credentials): bool
    {
        try {
            $token = $this->accessToken($credentials);
        } catch (DirectoryConnectionFailed) {
            return false;
        }

        return Http::withToken($token)->acceptJson()
            ->get(self::GRAPH.'/users?$top=1')
            ->successful();
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    private function accessToken(array $credentials): string
    {
        $tenant = $this->string($credentials, 'tenant_id');

        $response = Http::asForm()->post("https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token", [
            'client_id' => $this->string($credentials, 'client_id'),
            'client_secret' => $this->string($credentials, 'client_secret'),
            'scope' => 'https://graph.microsoft.com/.default',
            'grant_type' => 'client_credentials',
        ]);

        $token = $response->json('access_token');

        if (! $response->successful() || ! is_string($token) || $token === '') {
            throw DirectoryConnectionFailed::make('Microsoft Entra', 'Could not obtain a Graph access token.');
        }

        return $token;
    }

    /**
     * @param  array<string, mixed>  $user
     */
    private function toScimUser(array $user): ?ScimUser
    {
        $id = $user['id'] ?? null;
        $upn = $user['userPrincipalName'] ?? null;

        if (! is_string($id) || $id === '' || ! is_string($upn) || $upn === '') {
            return null;
        }

        $mail = is_string($user['mail'] ?? null) && $user['mail'] !== '' ? $user['mail'] : $upn;

        return new ScimUser(
            externalId: $id,
            userName: $upn,
            email: $mail,
            displayName: is_string($user['displayName'] ?? null) ? $user['displayName'] : null,
            active: ($user['accountEnabled'] ?? true) !== false,
            raw: $user,
        );
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    private function string(array $credentials, string $key): string
    {
        $value = $credentials[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw DirectoryConnectionFailed::make('Microsoft Entra', "Missing credential: {$key}.");
        }

        return $value;
    }
}
