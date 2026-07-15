<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Http\Request;

/**
 * Translates between the SCIM 2.0 User schema on the wire and the platform's
 * {@see ScimUser} value object / {@see DirectoryUser} model.
 */
final class ScimMapper
{
    /**
     * RFC 7643 §4.3 Enterprise User extension schema URN. Aliased to the shared
     * {@see ScimSchema} constant so the server and the outbound client speak the
     * exact same URN from one source.
     */
    public const ENTERPRISE_URN = ScimSchema::ENTERPRISE_URN;

    /** Enterprise-extension attributes IdPs actually provision. */
    private const ENTERPRISE_ATTRIBUTES = ['employeeNumber', 'costCenter', 'organization', 'division', 'department', 'manager'];

    public static function fromRequest(Request $request): ScimUser
    {
        $userName = $request->string('userName')->toString();
        $externalId = $request->string('externalId')->toString() ?: $userName;

        $emailRaw = $request->input('emails.0.value');
        $email = is_string($emailRaw) ? $emailRaw : null;

        $displayName = $request->string('displayName')->toString();
        if ($displayName === '') {
            $formatted = $request->input('name.formatted');
            $displayName = is_string($formatted) ? $formatted : $userName;
        }

        // NB: read the extension by literal top-level key — the URN contains a
        // dot ("2.0"), so $request->input() would misparse it as a nested path.
        $enterprise = $request->all()[self::ENTERPRISE_URN] ?? null;

        return self::build(
            $externalId,
            $userName,
            $email,
            $displayName,
            $request->boolean('active', true),
            self::normalizeEnterprise($enterprise),
        );
    }

    /**
     * Apply a SCIM PATCH request onto an existing user, returning the updated
     * resource to re-provision. Supports both `path`-based operations and the
     * pathless "replace whole value object" form (Azure/Entra), across the
     * attributes IdPs actually patch: active, userName, displayName,
     * name.formatted and emails.
     */
    public static function applyPatch(DirectoryUser $existing, Request $request): ScimUser
    {
        $resource = $existing->resource;
        $attributes = [
            'userName' => self::str($resource['userName'] ?? null),
            'externalId' => $existing->external_id,
            'email' => self::nullableStr($resource['email'] ?? null),
            'displayName' => self::nullableStr($resource['displayName'] ?? null),
            'active' => $existing->active,
            'enterprise' => self::normalizeEnterprise($resource['enterprise'] ?? null),
        ];

        $operations = $request->input('Operations');

        foreach (is_array($operations) ? $operations : [] as $operation) {
            if (! is_array($operation)) {
                continue;
            }

            $op = strtolower(self::str($operation['op'] ?? 'replace'));
            $path = $operation['path'] ?? null;
            $value = $operation['value'] ?? null;

            // `remove` clears the targeted attribute (RFC 7644 §3.5.2.2) rather
            // than being ignored — e.g. an IdP removing a user's display name.
            if ($op === 'remove') {
                if (is_string($path)) {
                    self::removeAttribute($attributes, $path);
                }

                continue;
            }

            if (is_string($path)) {
                self::setAttribute($attributes, $path, $value);
            } elseif (is_array($value)) {
                foreach ($value as $key => $nested) {
                    self::setAttribute($attributes, (string) $key, $nested);
                }
            }
        }

        return self::build(
            self::str($attributes['externalId']),
            self::str($attributes['userName']),
            self::nullableStr($attributes['email']),
            self::nullableStr($attributes['displayName']),
            (bool) $attributes['active'],
            self::normalizeEnterprise($attributes['enterprise']),
        );
    }

    /**
     * Build a SCIM ListResponse envelope.
     *
     * @param  list<array<string, mixed>>  $resources
     * @return array<string, mixed>
     */
    public static function listResponse(array $resources, int $totalResults, int $startIndex, int $itemsPerPage): array
    {
        return ScimSchema::listResponse($resources, $totalResults, $startIndex, $itemsPerPage);
    }

    /**
     * Clear a nullable attribute for a SCIM `remove` op. Required identifiers
     * (userName/externalId) and the `active` flag are not clearable this way — a
     * deactivation is a `replace active:false`, not a remove.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function removeAttribute(array &$attributes, string $path): void
    {
        match (strtolower($path)) {
            'displayname', 'name.formatted' => $attributes['displayName'] = null,
            'emails', 'emails[type eq "work"].value' => $attributes['email'] = null,
            default => null,
        };
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private static function setAttribute(array &$attributes, string $path, mixed $value): void
    {
        // Enterprise extension: paths arrive fully qualified with the schema URN
        // (Okta: "urn:...:User:department") or, pathless, as a nested object under
        // the URN key. Normalize either form onto the enterprise sub-array.
        if (self::applyEnterprisePatch($attributes, $path, $value)) {
            return;
        }

        match (strtolower($path)) {
            'active' => $attributes['active'] = filter_var($value, FILTER_VALIDATE_BOOLEAN),
            'username' => $attributes['userName'] = self::str($value),
            'displayname' => $attributes['displayName'] = self::str($value),
            'name.formatted' => $attributes['displayName'] = self::str($value),
            'emails', 'emails[type eq "work"].value' => $attributes['email'] = self::extractEmail($value),
            default => null,
        };
    }

    /**
     * Handle an enterprise-extension patch operation. Returns true when the path
     * belonged to the enterprise schema (and was applied), false otherwise.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function applyEnterprisePatch(array &$attributes, string $path, mixed $value): bool
    {
        $enterprise = is_array($attributes['enterprise'] ?? null) ? $attributes['enterprise'] : [];

        // Pathless nested object: { "urn:...:User": { "department": "..." } }
        if ($path === self::ENTERPRISE_URN && is_array($value)) {
            $attributes['enterprise'] = self::normalizeEnterprise(array_merge($enterprise, $value));

            return true;
        }

        // Fully-qualified single attribute: "urn:...:User:department"
        $prefix = self::ENTERPRISE_URN.':';
        if (str_starts_with($path, $prefix)) {
            $enterprise[substr($path, strlen($prefix))] = $value;
            $attributes['enterprise'] = self::normalizeEnterprise($enterprise);

            return true;
        }

        return false;
    }

    /**
     * Keep only the recognized enterprise attributes, dropping empties.
     *
     * @return array<string, mixed>
     */
    private static function normalizeEnterprise(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $out = [];
        foreach (self::ENTERPRISE_ATTRIBUTES as $key) {
            if (! array_key_exists($key, $value) || $value[$key] === null || $value[$key] === '') {
                continue;
            }
            $out[$key] = $value[$key];
        }

        return $out;
    }

    private static function extractEmail(mixed $value): ?string
    {
        if (is_string($value)) {
            return $value !== '' ? $value : null;
        }

        // emails as a list of {value: ...} — take the first usable address.
        if (is_array($value)) {
            foreach ($value as $entry) {
                if (is_array($entry) && isset($entry['value']) && is_string($entry['value'])) {
                    return $entry['value'];
                }
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $enterprise
     */
    private static function build(string $externalId, string $userName, ?string $email, ?string $displayName, bool $active, array $enterprise = []): ScimUser
    {
        $raw = [
            'userName' => $userName,
            'externalId' => $externalId,
            'email' => $email,
            'displayName' => $displayName,
            'active' => $active,
        ];

        if ($enterprise !== []) {
            $raw['enterprise'] = $enterprise;
        }

        return new ScimUser(
            externalId: $externalId,
            userName: $userName,
            email: $email,
            displayName: $displayName,
            active: $active,
            raw: $raw,
        );
    }

    private static function str(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    private static function nullableStr(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    public static function toResource(DirectoryUser $directoryUser): array
    {
        $resource = $directoryUser->resource;
        $displayName = self::nullableStr($resource['displayName'] ?? null);
        $email = self::nullableStr($resource['email'] ?? null);

        $out = [
            'schemas' => [ScimSchema::USER_URN],
            'id' => $directoryUser->id,
            'externalId' => $directoryUser->external_id,
            'userName' => self::str($resource['userName'] ?? null),
            'active' => $directoryUser->active,
            'meta' => [
                'resourceType' => 'User',
                'location' => '/scim/v2/Users/'.$directoryUser->id,
            ],
        ];

        if ($displayName !== null) {
            $out['displayName'] = $displayName;
            $out['name'] = ['formatted' => $displayName];
        }

        if ($email !== null) {
            $out['emails'] = [['value' => $email, 'primary' => true]];
        }

        $enterprise = self::normalizeEnterprise($resource['enterprise'] ?? null);
        if ($enterprise !== []) {
            $out['schemas'][] = self::ENTERPRISE_URN;
            $out[self::ENTERPRISE_URN] = $enterprise;
        }

        return $out;
    }
}
