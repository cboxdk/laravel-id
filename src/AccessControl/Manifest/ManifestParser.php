<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

use Cbox\Id\AccessControl\Exceptions\InvalidManifest;

/**
 * Parses + validates a raw manifest document (already JSON-decoded to an array)
 * into a typed {@see Manifest}. Deny-by-default: anything malformed — a bad key
 * format, a duplicate, or a role referencing an undeclared permission — is rejected
 * whole, never partially applied.
 */
class ManifestParser
{
    /** A `feature:action` (or bare `feature`) slug — lowercase, dot/colon/underscore/dash segments. */
    private const KEY_PATTERN = '/^[a-z][a-z0-9_-]*(?:[.:][a-z0-9_-]+)*$/';

    /**
     * @param  array<string, mixed>  $data
     */
    public function parse(array $data): Manifest
    {
        $version = $data['version'] ?? '';

        if (! is_string($version) || $version === '') {
            throw InvalidManifest::make('a non-empty "version" string is required.');
        }

        $permissions = $this->parsePermissions($data['permissions'] ?? []);
        $declaredKeys = array_map(static fn (DeclaredPermission $p): string => $p->key, $permissions);

        $roles = $this->parseRoles($data['roles'] ?? [], $declaredKeys);

        return new Manifest($version, $permissions, $roles);
    }

    /**
     * @param  mixed  $raw
     * @return list<DeclaredPermission>
     */
    private function parsePermissions($raw): array
    {
        if (! is_array($raw)) {
            throw InvalidManifest::make('"permissions" must be a list.');
        }

        $permissions = [];
        $seen = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
                throw InvalidManifest::make('each permission must be an object.');
            }

            $key = $this->requireKey($entry['key'] ?? null, 'permission');

            if (isset($seen[$key])) {
                throw InvalidManifest::make("duplicate permission \"{$key}\".");
            }
            $seen[$key] = true;

            $permissions[] = new DeclaredPermission(
                $key,
                $this->optionalString($entry['description'] ?? null),
                // Default true — an app opts a permission OUT of tenant self-serve by
                // declaring "tenant_assignable": false. Any non-false value stays true.
                ($entry['tenant_assignable'] ?? true) !== false,
            );
        }

        return $permissions;
    }

    /**
     * @param  mixed  $raw
     * @param  list<string>  $declaredPermissionKeys
     * @return list<DeclaredRole>
     */
    private function parseRoles($raw, array $declaredPermissionKeys): array
    {
        if (! is_array($raw)) {
            throw InvalidManifest::make('"roles" must be a list.');
        }

        $roles = [];
        $seen = [];
        $seenNames = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
                throw InvalidManifest::make('each role must be an object.');
            }

            $key = $this->requireKey($entry['key'] ?? null, 'role');

            if (isset($seen[$key])) {
                throw InvalidManifest::make("duplicate role \"{$key}\".");
            }
            $seen[$key] = true;

            $name = $entry['name'] ?? null;
            if (! is_string($name) || $name === '') {
                throw InvalidManifest::make("role \"{$key}\" needs a non-empty name.");
            }

            // Names must be distinct too — a person picking a role sees the name, and
            // two roles sharing one would be ambiguous (and collide in storage).
            $nameKey = mb_strtolower($name);
            if (isset($seenNames[$nameKey])) {
                throw InvalidManifest::make("duplicate role name \"{$name}\".");
            }
            $seenNames[$nameKey] = true;

            $permissions = $this->parseRolePermissions($entry['permissions'] ?? [], $key, $declaredPermissionKeys);

            $roles[] = new DeclaredRole($key, $name, $this->optionalString($entry['description'] ?? null), $permissions);
        }

        return $roles;
    }

    /**
     * @param  mixed  $raw
     * @param  list<string>  $declaredPermissionKeys
     * @return list<string>
     */
    private function parseRolePermissions($raw, string $roleKey, array $declaredPermissionKeys): array
    {
        if (! is_array($raw)) {
            throw InvalidManifest::make("role \"{$roleKey}\" permissions must be a list.");
        }

        $permissions = [];

        foreach ($raw as $permission) {
            if (! is_string($permission)) {
                throw InvalidManifest::make("role \"{$roleKey}\" has a non-string permission.");
            }

            // A role may only grant permissions the same manifest declares — no
            // dangling references.
            if (! in_array($permission, $declaredPermissionKeys, true)) {
                throw InvalidManifest::make("role \"{$roleKey}\" references undeclared permission \"{$permission}\".");
            }

            if (! in_array($permission, $permissions, true)) {
                $permissions[] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * @param  mixed  $value
     */
    private function requireKey($value, string $what): string
    {
        if (! is_string($value) || preg_match(self::KEY_PATTERN, $value) !== 1) {
            throw InvalidManifest::make("each {$what} needs a valid lowercase key (e.g. invoices:create).");
        }

        return $value;
    }

    /**
     * @param  mixed  $value
     */
    private function optionalString($value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
