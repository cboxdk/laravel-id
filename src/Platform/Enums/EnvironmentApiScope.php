<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

use Cbox\Id\Platform\Models\EnvironmentApiKey;

/**
 * The fine-grained permissions an environment API key can carry. Deny-by-default:
 * a key holds an explicit allow-list of scopes, and every management endpoint
 * requires exactly one. `resource:read` never implies `resource:write` — a
 * read-only integration key literally cannot mutate, so a leaked reporting key
 * can't be turned into a provisioning key.
 *
 * RESERVED scopes ({@see isReserved()}) stay valid on the keys that already hold them —
 * {@see EnvironmentApiKey::can()} still answers for them — but
 * no endpoint needs them yet, so a console must not offer them on a new key. Build pickers
 * and validation from {@see offerable()}, not from `cases()`.
 */
enum EnvironmentApiScope: string
{
    case OrganizationsRead = 'organizations:read';
    case OrganizationsWrite = 'organizations:write';
    case UsersRead = 'users:read';
    case UsersWrite = 'users:write';
    case DirectoriesRead = 'directories:read';
    case DirectoriesWrite = 'directories:write';

    case MembersRead = 'members:read';
    case MembersWrite = 'members:write';
    case InvitationsRead = 'invitations:read';
    case InvitationsWrite = 'invitations:write';
    case RolesRead = 'roles:read';
    case RolesWrite = 'roles:write';
    case AppsRead = 'apps:read';
    case AppsWrite = 'apps:write';
    case ApisRead = 'apis:read';
    case ApisWrite = 'apis:write';
    case ApiKeysRead = 'api_keys:read';
    case ApiKeysWrite = 'api_keys:write';
    case SupportWrite = 'support:write';

    public function label(): string
    {
        return match ($this) {
            self::OrganizationsRead => 'Read organizations',
            self::OrganizationsWrite => 'Manage organizations',
            self::UsersRead => 'Read users',
            self::UsersWrite => 'Manage users',
            self::DirectoriesRead => 'Read directories',
            self::DirectoriesWrite => 'Manage directories',
            self::MembersRead => 'Read members',
            self::MembersWrite => 'Manage members',
            self::InvitationsRead => 'Read invitations',
            self::InvitationsWrite => 'Manage invitations',
            self::RolesRead => 'Read roles',
            self::RolesWrite => 'Manage role assignments',
            self::AppsRead => 'Read apps',
            self::AppsWrite => 'Manage apps',
            self::ApisRead => 'Read APIs',
            self::ApisWrite => 'Manage APIs',
            self::ApiKeysRead => 'Read member API keys',
            self::ApiKeysWrite => 'Revoke member API keys',
            self::SupportWrite => 'Start support sessions',
        };
    }

    /** What a key holding this scope can do, in a sentence a person granting it can check. */
    public function description(): string
    {
        return match ($this) {
            self::OrganizationsRead => 'List organizations and read their details.',
            self::OrganizationsWrite => 'Create, rename and archive organizations, and transfer their ownership.',
            self::UsersRead => 'List users and read their profiles.',
            self::UsersWrite => 'Create, update and deactivate users.',
            self::DirectoriesRead => 'Reserved for directory sync. Not used by any endpoint yet.',
            self::DirectoriesWrite => 'Reserved for directory sync. Not used by any endpoint yet.',
            self::MembersRead => 'List an organization\'s members and their tiers.',
            self::MembersWrite => 'Add members, change their tier and remove them.',
            self::InvitationsRead => 'List an organization\'s pending invitations.',
            self::InvitationsWrite => 'Send, resend and revoke invitations.',
            self::RolesRead => 'List roles and read who holds them.',
            self::RolesWrite => 'Grant and take away roles, in one organization or across the environment.',
            self::AppsRead => 'List apps and export their configuration.',
            self::AppsWrite => 'Register apps and change their configuration.',
            self::ApisRead => 'List registered APIs and their scopes.',
            self::ApisWrite => 'Register, change and remove APIs and their scopes.',
            self::ApiKeysRead => 'List the API keys an organization\'s members created for your apps.',
            self::ApiKeysWrite => 'Revoke those API keys.',
            self::SupportWrite => 'Start a time-boxed support session acting for a user in one app.',
        };
    }

    /** Whether the scope lets a key change something, as opposed to only reading. */
    public function writes(): bool
    {
        return ! str_ends_with($this->value, ':read');
    }

    /**
     * Held by existing keys and still honoured, but not offered for new ones: no endpoint
     * needs it yet, and a scope that grants nothing is a box an administrator ticks to no
     * effect — or, worse, ticks today and finds meaning something tomorrow.
     */
    public function isReserved(): bool
    {
        return match ($this) {
            self::DirectoriesRead, self::DirectoriesWrite => true,
            default => false,
        };
    }

    /**
     * Every scope, for the "full access" key an admin can mint. Reserved scopes included,
     * so an existing full-access key keeps validating against this list; new keys should
     * be built from {@see offerable()}.
     *
     * @return list<string>
     */
    public static function all(): array
    {
        return array_map(static fn (self $s): string => $s->value, self::cases());
    }

    /**
     * The scopes a console or API may grant to a NEW key: every case that is not reserved.
     *
     * @return list<self>
     */
    public static function offerable(): array
    {
        return array_values(array_filter(self::cases(), static fn (self $s): bool => ! $s->isReserved()));
    }

    /**
     * {@see offerable()} as wire values, for validation (`Rule::in(...)`).
     *
     * @return list<string>
     */
    public static function offerableValues(): array
    {
        return array_map(static fn (self $s): string => $s->value, self::offerable());
    }
}
