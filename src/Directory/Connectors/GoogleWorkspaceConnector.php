<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Connectors;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\ValueObjects\DirectoryGroupSnapshot;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Pulls users from Google Workspace via the Admin SDK Directory API. Google has no
 * SCIM, so this API-pull is the only integration path. Auth is a service account
 * with domain-wide delegation: we mint a signed JWT (RS256, the SA private key),
 * exchange it for an access token impersonating an admin (`admin_email`), and page
 * the users list. Credentials: `client_email`, `private_key`, `admin_email`, and an
 * optional `customer_id` (default `my_customer`). Read-only scope; suspended Google
 * accounts arrive inactive so the reconciliation deprovisions them.
 */
final class GoogleWorkspaceConnector implements DirectoryConnector
{
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';

    private const DIRECTORY_URL = 'https://admin.googleapis.com/admin/directory/v1/users';

    private const GROUPS_URL = 'https://admin.googleapis.com/admin/directory/v1/groups';

    private const SCOPE = 'https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly';

    public function provider(): DirectoryProvider
    {
        return DirectoryProvider::GoogleWorkspace;
    }

    public function fetchUsers(array $credentials): iterable
    {
        $token = $this->accessToken($credentials);
        $customer = is_string($credentials['customer_id'] ?? null) && $credentials['customer_id'] !== ''
            ? $credentials['customer_id']
            : 'my_customer';

        $pageToken = null;

        do {
            $response = Http::withToken($token)->acceptJson()->get(self::DIRECTORY_URL, array_filter([
                'customer' => $customer,
                'maxResults' => 200,
                'pageToken' => $pageToken,
            ], fn ($v) => $v !== null));

            if ($response->failed()) {
                throw DirectoryConnectionFailed::make('Google Workspace', 'Directory users request failed ('.$response->status().').');
            }

            /** @var array<int, array<string, mixed>> $users */
            $users = $response->json('users', []);

            foreach ($users as $user) {
                $scim = $this->toScimUser($user);

                if ($scim !== null) {
                    yield $scim;
                }
            }

            $next = $response->json('nextPageToken');
            $pageToken = is_string($next) && $next !== '' ? $next : null;
        } while ($pageToken !== null);
    }

    public function fetchGroups(array $credentials): iterable
    {
        $token = $this->accessToken($credentials);
        $customer = is_string($credentials['customer_id'] ?? null) && $credentials['customer_id'] !== ''
            ? $credentials['customer_id']
            : 'my_customer';

        $pageToken = null;

        do {
            $response = Http::withToken($token)->acceptJson()->get(self::GROUPS_URL, array_filter([
                'customer' => $customer,
                'maxResults' => 200,
                'pageToken' => $pageToken,
            ], fn ($v) => $v !== null));

            if ($response->failed()) {
                throw DirectoryConnectionFailed::make('Google Workspace', 'Directory groups request failed ('.$response->status().').');
            }

            /** @var array<int, array<string, mixed>> $groups */
            $groups = $response->json('groups', []);

            foreach ($groups as $group) {
                $id = $group['id'] ?? null;
                $name = is_string($group['name'] ?? null) && $group['name'] !== '' ? $group['name'] : ($group['email'] ?? null);

                if (is_string($id) && $id !== '' && is_string($name) && $name !== '') {
                    yield new DirectoryGroupSnapshot($id, $name, $this->groupMembers($token, $id));
                }
            }

            $next = $response->json('nextPageToken');
            $pageToken = is_string($next) && $next !== '' ? $next : null;
        } while ($pageToken !== null);
    }

    /**
     * @return list<string>
     */
    private function groupMembers(string $token, string $groupId): array
    {
        $ids = [];
        $pageToken = null;

        do {
            $response = Http::withToken($token)->acceptJson()->get(self::GROUPS_URL.'/'.$groupId.'/members', array_filter([
                'maxResults' => 200,
                'pageToken' => $pageToken,
            ], fn ($v) => $v !== null));

            // A partial membership is better than failing the whole sync.
            if ($response->failed()) {
                break;
            }

            /** @var array<int, array<string, mixed>> $members */
            $members = $response->json('members', []);

            foreach ($members as $member) {
                if (($member['type'] ?? null) === 'USER' && is_string($member['id'] ?? null)) {
                    $ids[] = $member['id'];
                }
            }

            $next = $response->json('nextPageToken');
            $pageToken = is_string($next) && $next !== '' ? $next : null;
        } while ($pageToken !== null);

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
            ->get(self::DIRECTORY_URL, ['customer' => 'my_customer', 'maxResults' => 1])
            ->successful();
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    private function accessToken(array $credentials): string
    {
        $now = time();

        try {
            // A signed JWT asserting the service account, impersonating the admin.
            $assertion = JWT::encode([
                'iss' => $this->string($credentials, 'client_email'),
                'sub' => $this->string($credentials, 'admin_email'),
                'scope' => self::SCOPE,
                'aud' => self::TOKEN_URL,
                'iat' => $now,
                'exp' => $now + 3600,
            ], $this->string($credentials, 'private_key'), 'RS256');
        } catch (Throwable $e) {
            throw DirectoryConnectionFailed::make('Google Workspace', 'Could not sign the service-account assertion: '.$e->getMessage());
        }

        $response = Http::asForm()->post(self::TOKEN_URL, [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $assertion,
        ]);

        $token = $response->json('access_token');

        if (! $response->successful() || ! is_string($token) || $token === '') {
            throw DirectoryConnectionFailed::make('Google Workspace', 'Could not obtain an Admin SDK access token.');
        }

        return $token;
    }

    /**
     * @param  array<string, mixed>  $user
     */
    private function toScimUser(array $user): ?ScimUser
    {
        $id = $user['id'] ?? null;
        $email = $user['primaryEmail'] ?? null;

        if (! is_string($id) || $id === '' || ! is_string($email) || $email === '') {
            return null;
        }

        $name = $user['name'] ?? null;
        $displayName = is_array($name) && is_string($name['fullName'] ?? null) ? $name['fullName'] : null;

        return new ScimUser(
            externalId: $id,
            userName: $email,
            email: $email,
            displayName: $displayName,
            active: ($user['suspended'] ?? false) !== true,
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
            throw DirectoryConnectionFailed::make('Google Workspace', "Missing credential: {$key}.");
        }

        return $value;
    }
}
