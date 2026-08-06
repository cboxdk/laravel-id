<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

/**
 * The fine-grained permissions an environment API key can carry. Deny-by-default:
 * a key holds an explicit allow-list of scopes, and every management endpoint
 * requires exactly one. `resource:read` never implies `resource:write` — a
 * read-only integration key literally cannot mutate, so a leaked reporting key
 * can't be turned into a provisioning key.
 */
enum EnvironmentApiScope: string
{
    case OrganizationsRead = 'organizations:read';
    case OrganizationsWrite = 'organizations:write';
    case UsersRead = 'users:read';
    case UsersWrite = 'users:write';
    case DirectoriesRead = 'directories:read';
    case DirectoriesWrite = 'directories:write';

    public function label(): string
    {
        return match ($this) {
            self::OrganizationsRead => 'Read organizations',
            self::OrganizationsWrite => 'Manage organizations',
            self::UsersRead => 'Read users',
            self::UsersWrite => 'Manage users',
            self::DirectoriesRead => 'Read directories',
            self::DirectoriesWrite => 'Manage directories',
        };
    }

    /**
     * Every scope, for the "full access" key an admin can mint.
     *
     * @return list<string>
     */
    public static function all(): array
    {
        return array_map(static fn (self $s): string => $s->value, self::cases());
    }
}
