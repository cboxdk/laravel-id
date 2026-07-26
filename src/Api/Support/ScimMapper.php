<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Api\Exceptions\UnsupportedScimPath;
use Cbox\Id\Api\Http\Controllers\Scim\ScimController;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Scim\Enums\ScimPatchOp;
use Cbox\Id\Scim\ScimSchema;
use Cbox\Id\Scim\Support\ScimBoolean;
use Illuminate\Http\Request;

/**
 * Translates between the SCIM 2.0 User schema on the wire and the platform's
 * {@see ScimUser} value object / {@see DirectoryUser} model.
 */
class ScimMapper
{
    /**
     * RFC 7643 §4.3 Enterprise User extension schema URN. Aliased to the shared
     * {@see ScimSchema} constant so the server and the outbound client speak the
     * exact same URN from one source.
     */
    public const ENTERPRISE_URN = ScimSchema::ENTERPRISE_URN;

    /** Enterprise-extension attributes IdPs actually provision. */
    private const ENTERPRISE_ATTRIBUTES = ['employeeNumber', 'costCenter', 'organization', 'division', 'department', 'manager'];

    /**
     * Map an inbound SCIM User payload to a {@see ScimUser}.
     *
     * On PUT (full replace) the resource identity is the URL, not the body: pass
     * `$externalId` to pin it to the located row. Without that pin an omitted
     * `externalId` falls back to `userName` below, which would re-key the write to
     * a DIFFERENT row (create/overwrite the wrong user) — see {@see UserController::replace()}.
     */
    public static function fromRequest(Request $request, ?string $externalId = null): ScimUser
    {
        $userName = $request->string('userName')->toString();
        $externalId ??= $request->string('externalId')->toString() ?: $userName;

        $email = self::extractEmail($request->input('emails'));

        // Okta's default SCIM profile sends the name PARTS and NEVER name.formatted or
        // displayName. Reading only `name.formatted` here meant a create landed with no
        // stored name at all: displayName fell back to the userName (an email address),
        // and a later single-part PATCH had nothing to merge against. The parts are
        // persisted, and the display name is composed from them.
        $givenName = self::nullableStr($request->input('name.givenName'));
        $familyName = self::nullableStr($request->input('name.familyName'));

        $displayName = $request->string('displayName')->toString();
        if ($displayName === '') {
            $formatted = self::nullableStr($request->input('name.formatted'));
            $displayName = $formatted ?? trim(($givenName ?? '').' '.($familyName ?? ''));
        }

        // NB: read the extension by literal top-level key — the URN contains a
        // dot ("2.0"), so $request->input() would misparse it as a nested path.
        $enterprise = $request->all()[self::ENTERPRISE_URN] ?? null;

        return self::build(
            $externalId,
            $userName,
            $email,
            $displayName !== '' ? $displayName : $userName,
            self::activeFromRequest($request),
            self::normalizeEnterprise($enterprise),
            $givenName,
            $familyName,
        );
    }

    /**
     * The `active` flag of a create/replace body.
     *
     * RFC 7643 §4.1.1 makes `active` optional and an absent (or explicitly null) value
     * means "in service", so it defaults to true. A PRESENT but unparsable value is a
     * client error: `Request::boolean()` coerced `"fasle"`, `"no"` and `0` to false,
     * which on this code path deactivates the account, drops org membership and revokes
     * every session — a deprovision caused by a typo, reported to the IdP as success.
     */
    private static function activeFromRequest(Request $request): bool
    {
        $value = $request->input('active');

        if ($value === null) {
            return true;
        }

        return ScimBoolean::parse($value) ?? throw InvalidScimRequest::notABoolean('active');
    }

    /**
     * Apply a SCIM PATCH request onto an existing user, returning the updated
     * resource to re-provision. Supports both `path`-based operations and the
     * pathless "replace whole value object" form (Azure/Entra), across the
     * attributes IdPs actually patch: active, userName, displayName, the `name`
     * sub-attributes and emails.
     *
     * The operations arrive already validated as a non-empty list of objects (see
     * {@see ScimController::operations()}) — a
     * missing or misspelled `Operations` member never reaches here as "no work to do".
     *
     * @param  list<array<array-key, mixed>>  $operations
     *
     * @throws InvalidScimRequest
     */
    public static function applyPatch(DirectoryUser $existing, array $operations): ScimUser
    {
        $resource = $existing->resource;
        $attributes = [
            // Seeded from the stored parts: without them a PATCH that sets only
            // familyName composed from that one alone — "Dana Rivera" + {familyName:
            // "Okonkwo"} silently became "Okonkwo".
            'givenName' => self::nullableStr($resource['givenName'] ?? null),
            'familyName' => self::nullableStr($resource['familyName'] ?? null),
            'userName' => self::str($resource['userName'] ?? null),
            'externalId' => $existing->external_id,
            'email' => self::nullableStr($resource['email'] ?? null),
            'displayName' => self::nullableStr($resource['displayName'] ?? null),
            'active' => $existing->active,
            'enterprise' => self::normalizeEnterprise($resource['enterprise'] ?? null),
        ];

        /** @var list<string> $touched canonical paths this request explicitly set */
        $touched = [];

        foreach ($operations as $operation) {
            // Deny-by-default: RFC 7644 §3.5.2 defines only add/remove/replace, and the
            // enum is the single source of that list (the Group path parses it the same
            // way). An unknown or missing op is a client error — a 400 `invalidSyntax`,
            // never a silent 200 that lets the IdP believe a mis-typed write applied.
            $op = ScimPatchOp::tryParse($operation['op'] ?? null)
                ?? throw UnsupportedScimPath::forOp(ScimPatchOp::label($operation['op'] ?? null));

            $path = $operation['path'] ?? null;
            $value = $operation['value'] ?? null;

            // `remove` clears the targeted attribute (RFC 7644 §3.5.2.2) rather
            // than being ignored — e.g. an IdP removing a user's display name.
            if ($op === ScimPatchOp::Remove) {
                // §3.5.2.2 is explicit: "If 'path' is unspecified, the operation fails
                // with HTTP status code 400 and a 'scimType' error code of 'noTarget'."
                // Falling through to `continue` answered 200 for an op that named
                // nothing and did nothing — the same silent success every other guard
                // on this path exists to prevent.
                if (! is_string($path) || trim($path) === '') {
                    throw InvalidScimRequest::noTarget();
                }

                if (! self::removeAttribute($attributes, $path)) {
                    throw UnsupportedScimPath::forPath($path);
                }

                continue;
            }

            if (is_string($path)) {
                if (! self::setAttribute($attributes, $path, $value, $touched)) {
                    throw UnsupportedScimPath::forPath($path);
                }
            } elseif (is_array($value)) {
                // A pathless operation carries a partial resource; each key is a path.
                // Unknown keys here are tolerated rather than fatal — an IdP routinely
                // sends the whole resource, including attributes we deliberately do not
                // map — whereas an explicit `path` names ONE target and expects it hit.
                //
                // Tolerated is not the same as DISCARDED: the return value used to be
                // thrown away wholesale, so Entra's pathless `{"name": {...}}` mapping
                // was dropped on every push while the identical content under an explicit
                // path was a hard 400. setAttribute now descends into complex values, so
                // both spellings land — and both register in $touched below.
                foreach ($value as $key => $nested) {
                    self::setAttribute($attributes, (string) $key, $nested, $touched);
                }
            }
        }

        // Recompose the display name from the name PARTS whenever this request set them
        // and did not also set an explicit displayName.
        //
        // Not just "when displayName is empty": it is seeded from the stored resource,
        // which for an Okta-provisioned user is their email address (the fallback in
        // build()). So a later givenName/familyName push would never take effect and the
        // user would keep an email address as their name forever.
        $patchedParts = in_array('name.givenname', $touched, true) || in_array('name.familyname', $touched, true);
        $patchedDisplayName = in_array('displayname', $touched, true) || in_array('name.formatted', $touched, true);

        if ($patchedParts && ! $patchedDisplayName) {
            $composed = trim(self::str($attributes['givenName'] ?? '').' '.self::str($attributes['familyName'] ?? ''));

            if ($composed !== '') {
                $attributes['displayName'] = $composed;
            }
        }

        return self::build(
            self::str($attributes['externalId']),
            self::str($attributes['userName']),
            self::nullableStr($attributes['email']),
            self::nullableStr($attributes['displayName']),
            (bool) $attributes['active'],
            self::normalizeEnterprise($attributes['enterprise']),
            self::nullableStr($attributes['givenName'] ?? null),
            self::nullableStr($attributes['familyName'] ?? null),
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
    private static function removeAttribute(array &$attributes, string $path): bool
    {
        // NB: assign directly, never through a closure — $attributes is by-reference and
        // an arrow function would capture it by VALUE, silently discarding every write.
        switch (self::canonicalPath($path)) {
            case 'displayname':
            case 'name.formatted':
                $attributes['displayName'] = null;

                return true;
            case 'name.givenname':
                $attributes['givenName'] = null;

                return true;
            case 'name.familyname':
                $attributes['familyName'] = null;

                return true;
            case 'emails':
                $attributes['email'] = null;

                return true;
            default:
                // Same tolerated set as setAttribute: removing an attribute we never
                // stored is a no-op by definition, not a protocol error.
                return self::isTolerated(self::canonicalPath($path));
        }
    }

    /**
     * Reduce a PATCH path to the attribute it targets.
     *
     * Paths arrive with value filters — `emails[type eq "work"].value` — and the filter
     * varies by IdP and even by mapping (`emails[type eq "work"].value`,
     * `emails[type EQ "work"].value`, a different type). Matching the whole string as a
     * literal meant one exact spelling worked and every variant fell through to a silent
     * no-op, so an IdP saw 200 OK and recorded a successful write that never happened.
     */
    private static function canonicalPath(string $path): string
    {
        // Strip any [ ... ] value filter, then the trailing sub-attribute it selected.
        $canonical = strtolower(trim($path));
        $canonical = (string) preg_replace('/\[[^\]]*\]/', '', $canonical);
        $canonical = (string) preg_replace('/^(emails|phonenumbers)\.value$/', '$1', $canonical);

        return trim($canonical, '.');
    }

    /**
     * Apply one attribute of a PATCH operation, recording the canonical path in
     * `$touched` when a value was actually written. Returns false when the path names
     * something this server cannot interpret at all (the caller turns that into a 400).
     *
     * @param  array<string, mixed>  $attributes
     * @param  list<string>  $touched
     *
     * @throws InvalidScimRequest
     */
    private static function setAttribute(array &$attributes, string $path, mixed $value, array &$touched): bool
    {
        // Enterprise extension: paths arrive fully qualified with the schema URN
        // (Okta: "urn:...:User:department") or, pathless, as a nested object under
        // the URN key. Normalize either form onto the enterprise sub-array.
        if (self::applyEnterprisePatch($attributes, $path, $value)) {
            $touched[] = self::canonicalPath($path);

            return true;
        }

        $canonical = self::canonicalPath($path);

        switch ($canonical) {
            case 'active':
                // Strict, never coercive: FILTER_VALIDATE_BOOLEAN answered false for any
                // value it did not recognise, so `"active": "fasle"` deactivated the
                // subject, dropped membership and revoked every session — and the IdP
                // recorded it as a successful write.
                $attributes['active'] = ScimBoolean::parse($value)
                    ?? throw InvalidScimRequest::notABoolean('active');
                break;
            case 'username':
                $attributes['userName'] = self::str($value);
                break;
            case 'displayname':
            case 'name.formatted':
                $attributes['displayName'] = self::str($value);
                break;
                // Okta's default SCIM profile sends givenName/familyName and NEVER
                // name.formatted or displayName. Dropping them meant every Okta-provisioned
                // user's display name fell back to their email address, permanently.
            case 'name.givenname':
                $attributes['givenName'] = self::str($value);
                break;
            case 'name.familyname':
                $attributes['familyName'] = self::str($value);
                break;
            case 'emails':
                $attributes['email'] = self::extractEmail($value);
                break;
            case 'name':
                // The whole complex attribute in one value — what Entra's PATHLESS
                // mapping sends, and what an explicit `"path": "name"` op sends. Recurse
                // so each sub-attribute takes exactly the same route (and the same
                // $touched bookkeeping) as its dotted spelling.
                return self::setComplexAttribute($attributes, 'name', $value, $touched);
            default:
                return self::isTolerated($canonical);
        }

        $touched[] = $canonical;

        return true;
    }

    /**
     * Apply a complex attribute supplied as a whole object by descending into its
     * sub-attributes.
     *
     * @param  array<string, mixed>  $attributes
     * @param  list<string>  $touched
     */
    private static function setComplexAttribute(array &$attributes, string $path, mixed $value, array &$touched): bool
    {
        if (! is_array($value)) {
            return false;
        }

        foreach ($value as $key => $sub) {
            if (! self::setAttribute($attributes, $path.'.'.$key, $sub, $touched)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Attributes this server knowingly does not persist, but must not REFUSE.
     *
     * RFC 7644 §3.5.2's invalidPath is about a path the SCHEMA does not define — not an
     * attribute the server chooses not to store. Throwing for these turned a silent
     * no-op into a hard failure on the operations that matter most: Entra's default
     * mapping ships phoneNumbers, and applyPatch throws mid-loop, so a deprovision push
     * of [{active:false},{phoneNumbers…}] returned 400 and the user was NEVER
     * DEACTIVATED. Entra then quarantines the provisioning job after repeated failures.
     *
     * So: accept and ignore what we understand but don't keep; refuse only what we
     * cannot interpret at all.
     */
    private static function isTolerated(string $canonicalPath): bool
    {
        return in_array($canonicalPath, [
            'phonenumbers',
            'addresses',
            'photos',
            'ims',
            'roles',
            'groups',
            'entitlements',
            'x509certificates',
            'title',
            'usertype',
            'nickname',
            'profileurl',
            'preferredlanguage',
            'locale',
            'timezone',
            'name.middlename',
            'name.honorificprefix',
            'name.honorificsuffix',
        ], true);
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
            $attribute = substr($path, strlen($prefix));

            // Same split as the core schema: an attribute of the extension we simply do
            // not persist is TOLERATED (accepted, ignored), but one that is not part of
            // the extension at all is refused. Previously every unsupported attribute
            // returned 200 and was then silently dropped by normalizeEnterprise() — the
            // IdP recorded a write that never happened.
            // ENTERPRISE_ATTRIBUTES already IS the full RFC 7643 §4.3 set, so anything
            // else is genuinely undefined by the schema — refuse it. Previously any
            // unsupported attribute returned 200 and was then silently dropped by
            // normalizeEnterprise(), so the IdP recorded a write that never happened.
            if (! in_array($attribute, self::ENTERPRISE_ATTRIBUTES, true)) {
                return false;
            }

            $enterprise[$attribute] = $value;
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

    /**
     * The single address this platform keeps out of a SCIM `emails` multi-value.
     *
     * RFC 7643 §2.4: at most one value of a multi-valued attribute may be `primary`,
     * and it is the preferred one. Taking the first entry regardless meant an IdP that
     * lists `home` before `work` (Entra does, for some profiles) provisioned the wrong
     * address — and email is the platform's account identity.
     */
    private static function extractEmail(mixed $value): ?string
    {
        if (is_string($value)) {
            return $value !== '' ? $value : null;
        }

        if (! is_array($value)) {
            return null;
        }

        $first = null;

        foreach ($value as $entry) {
            $address = self::nullableStr(is_array($entry) ? ($entry['value'] ?? null) : $entry);

            if ($address === null) {
                continue;
            }

            if (is_array($entry) && ($entry['primary'] ?? null) === true) {
                return $address;
            }

            $first ??= $address;
        }

        return $first;
    }

    /**
     * @param  array<string, mixed>  $enterprise
     */
    private static function build(string $externalId, string $userName, ?string $email, ?string $displayName, bool $active, array $enterprise = [], ?string $givenName = null, ?string $familyName = null): ScimUser
    {
        $raw = [
            'userName' => $userName,
            'externalId' => $externalId,
            'email' => $email,
            'displayName' => $displayName,
            'active' => $active,
        ];

        // Persist the name PARTS, not just the composed display name. Without them a
        // later PATCH of one part has nothing to merge with and silently drops the other.
        if ($givenName !== null) {
            $raw['givenName'] = $givenName;
        }

        if ($familyName !== null) {
            $raw['familyName'] = $familyName;
        }

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

    /**
     * The absolute URI of a User resource — `meta.location` and `Content-Location` both.
     */
    public static function location(string $id): string
    {
        return rtrim((string) url('/'), '/').'/scim/v2/Users/'.$id;
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
            // created/lastModified are mandatory for any connector doing delta sync
            // (`meta.lastModified gt "<watermark>"`). Omitting them left every
            // connector no choice but a FULL sweep on each run — straight into the
            // rate limit, on a schedule.
            // An ABSOLUTE URI, and the same one the response's Content-Location header
            // carries: RFC 7643 §3.1 defines meta.location as "The URI of the resource"
            // and RFC 7644 §3.1 requires the two to be equal. A relative path is neither
            // a URI nor equal to a header the server was not sending at all, and a
            // connector that follows meta.location — Okta does, to re-read a resource
            // after a write — resolved it against its own base and 404'd.
            'meta' => ScimSchema::meta(
                'User',
                self::location($directoryUser->id),
                $directoryUser->created_at,
                $directoryUser->updated_at,
            ),
        ];

        if ($displayName !== null) {
            $out['displayName'] = $displayName;
        }

        // The name PARTS, not just the composed `formatted`. /Schemas declares
        // givenName/familyName and both are persisted and accepted on write, so
        // omitting them here broke the resource in two directions at once: an Okta
        // admin who mapped `user.firstName ← name.givenName` imported every user with a
        // blank first name, and Entra's read-modify-write PUT reconciliation read the
        // resource back WITHOUT them and pushed that omission straight over the stored
        // values — blanking them on the next cycle.
        $name = array_filter([
            'formatted' => $displayName,
            'givenName' => self::nullableStr($resource['givenName'] ?? null),
            'familyName' => self::nullableStr($resource['familyName'] ?? null),
        ], static fn (?string $value): bool => $value !== null);

        if ($name !== []) {
            $out['name'] = $name;
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
