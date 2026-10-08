<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Api\Exceptions\InvalidScimRequest;
use Cbox\Id\Api\Exceptions\UnsupportedScimPath;
use Cbox\Id\Api\Http\Controllers\Scim\ScimController;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Scim\Enums\ScimPatchOp;
use Cbox\Id\Scim\Exceptions\InvalidScimFilter;
use Cbox\Id\Scim\Filter\ScimFilterEvaluator;
use Cbox\Id\Scim\Filter\ScimFilterParser;
use Cbox\Id\Scim\Filter\ScimPatchPath;
use Cbox\Id\Scim\ScimSchema;
use Cbox\Id\Scim\Support\ScimBoolean;
use Cbox\Id\Scim\Support\ScimETag;
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
        return self::fromArray($request->all(), $externalId);
    }

    /**
     * {@see fromRequest()} over a decoded body — the `data` of a `/Bulk` operation is
     * read by exactly the same rules as a single-resource request.
     *
     * @param  array<array-key, mixed>  $body
     *
     * @throws InvalidScimRequest
     */
    public static function fromArray(array $body, ?string $externalId = null): ScimUser
    {
        // Read case-insensitively (RFC 7643 §2.1). PATCH has always lowercased its paths;
        // POST and PUT read exact casing, so a provisioner sending `UserName` had it
        // silently read as empty — see ScimAttributes.
        $userName = ScimAttributes::stringValue($body, 'userName');
        $externalId ??= ScimAttributes::stringValue($body, 'externalId') ?: $userName;

        $email = self::extractEmail(ScimAttributes::value($body, 'emails'));

        // Okta's default SCIM profile sends the name PARTS and NEVER name.formatted or
        // displayName. Reading only `name.formatted` here meant a create landed with no
        // stored name at all: displayName fell back to the userName (an email address),
        // and a later single-part PATCH had nothing to merge against. The parts are
        // persisted, and the display name is composed from them.
        $givenName = self::nullableStr(ScimAttributes::value($body, 'name.givenName'));
        $familyName = self::nullableStr(ScimAttributes::value($body, 'name.familyName'));

        $displayName = ScimAttributes::stringValue($body, 'displayName');
        if ($displayName === '') {
            $formatted = self::nullableStr(ScimAttributes::value($body, 'name.formatted'));
            $displayName = $formatted ?? trim(($givenName ?? '').' '.($familyName ?? ''));
        }

        // NB: read the extension by its top-level key, never as a dot path — the URN
        // contains a dot ("2.0"), which a dot-path reader would split.
        $enterprise = self::topLevel($body, self::ENTERPRISE_URN);

        return self::build(
            $externalId,
            $userName,
            $email,
            $displayName !== '' ? $displayName : $userName,
            self::activeFrom(ScimAttributes::value($body, 'active')),
            self::normalizeEnterprise(is_array($enterprise) ? self::enterpriseKeys($enterprise) : null),
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
    private static function activeFrom(mixed $value): bool
    {
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

                if (! self::removePath($attributes, $path)) {
                    throw UnsupportedScimPath::forPath($path);
                }

                continue;
            }

            if (is_string($path)) {
                if (! self::setPath($attributes, $path, $value, $touched)) {
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
                    self::setPath($attributes, (string) $key, $nested, $touched);
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
     * The canonical spelling of each Enterprise User attribute (RFC 7643 §4.3), keyed by
     * its folded name — paths arrive in any case (RFC 7643 §2.1).
     */
    private const ENTERPRISE_NAMES = [
        'employeenumber' => 'employeeNumber',
        'costcenter' => 'costCenter',
        'organization' => 'organization',
        'division' => 'division',
        'department' => 'department',
        'manager' => 'manager',
    ];

    /** The sub-attributes of the Enterprise `manager` (RFC 7643 §4.3). */
    private const MANAGER_FIELDS = ['value' => 'value', '$ref' => '$ref', 'displayname' => 'displayName'];

    /**
     * Core attributes this server addresses by name — anything else unqualified that the
     * Enterprise extension defines is read as the extension's (see {@see resolve()}).
     */
    private const CORE_ATTRIBUTES = ['active', 'username', 'displayname', 'name', 'emails', 'externalid', 'id'];

    /**
     * Multi-valued core attributes this server does not store, whose values a PATCH may
     * address one at a time (`phoneNumbers[type eq "mobile"].value`,
     * `addresses[type eq "work"].streetAddress`). Accepted and ignored, like the
     * attribute itself — see {@see isTolerated()}.
     */
    private const TOLERATED_MULTI_VALUED = ['phonenumbers', 'addresses', 'photos', 'ims', 'roles', 'groups', 'entitlements', 'x509certificates'];

    /**
     * Clear an attribute for a SCIM `remove` op (RFC 7644 §3.5.2.2). Required
     * identifiers (userName/externalId) and the `active` flag are not clearable this
     * way — a deactivation is a `replace active:false`, not a remove.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function removePath(array &$attributes, string $path): bool
    {
        if (strcasecmp(trim($path), self::ENTERPRISE_URN) === 0) {
            $attributes['enterprise'] = [];

            return true;
        }

        $parsed = self::parsePath($path);

        if ($parsed === null) {
            return self::unparsableIsTolerated($path);
        }

        [$schema, $parsed] = $parsed;

        if ($schema === 'enterprise') {
            return self::removeEnterprise($attributes, $parsed);
        }

        if ($schema !== 'core') {
            return false;
        }

        if ($parsed->filter !== null) {
            return self::removeFiltered($attributes, $parsed);
        }

        // NB: assign directly, never through a closure — $attributes is by-reference and
        // an arrow function would capture it by VALUE, silently discarding every write.
        switch (self::target($parsed)) {
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
            case 'name':
                $attributes['givenName'] = null;
                $attributes['familyName'] = null;

                return true;
            case 'emails':
                $attributes['email'] = null;

                return true;
            default:
                // Same tolerated set as setPath: removing an attribute we never stored
                // is a no-op by definition, not a protocol error.
                return self::isTolerated(self::target($parsed));
        }
    }

    /**
     * A `remove` that selects values with a filter: `emails[type eq "work"]`. Only the
     * stored address can be removed, and only when the filter selects it.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function removeFiltered(array &$attributes, ScimPatchPath $path): bool
    {
        $attribute = strtolower($path->attribute->attribute);

        if ($attribute === 'emails') {
            if (in_array($path->subAttribute, [null, 'value'], true) && self::selectsStoredEmail($path, $attributes)) {
                $attributes['email'] = null;
            }

            return true;
        }

        return in_array($attribute, self::TOLERATED_MULTI_VALUED, true);
    }

    /**
     * The path parsed by the RFC 7644 grammar, with the schema it belongs to: `core`
     * (unqualified, or qualified with the core User URN), `enterprise` (qualified with
     * the Enterprise User URN, or an unqualified name only the extension defines), or
     * `other` (some other URN this server does not implement). Null when the path does
     * not parse at all.
     *
     * The unqualified fallback exists because Microsoft Entra ID patches the manager as
     * `"path": "manager"` — and RFC 7644 §3.10 only says extension attributes SHOULD be
     * qualified.
     *
     * @return array{'core'|'enterprise'|'other', ScimPatchPath}|null
     */
    private static function parsePath(string $path): ?array
    {
        try {
            $parsed = (new ScimFilterParser)->parsePath($path);
        } catch (InvalidScimFilter) {
            return null;
        }

        $attribute = $parsed->attribute;

        if ($attribute->schema !== null) {
            return match (true) {
                $attribute->inSchema(ScimSchema::USER_URN) => ['core', $parsed],
                $attribute->inSchema(self::ENTERPRISE_URN) => ['enterprise', $parsed],
                default => ['other', $parsed],
            };
        }

        $name = strtolower($attribute->attribute);

        if (! in_array($name, self::CORE_ATTRIBUTES, true) && array_key_exists($name, self::ENTERPRISE_NAMES)) {
            return ['enterprise', $parsed];
        }

        return ['core', $parsed];
    }

    /**
     * What a parsed core path writes: `emails[type eq "work"].value` and
     * `emails.value` both write `emails`, the one address this server stores.
     */
    private static function target(ScimPatchPath $path): string
    {
        return (string) preg_replace('/^(emails|phonenumbers)\.value$/', '$1', $path->target());
    }

    /**
     * A path the grammar cannot read. Refused — unless it plainly addresses a value of
     * a multi-valued attribute this server either does not store or stores only as the
     * primary address, where an IdP-specific filter spelling must not fail the whole
     * (atomic) PATCH: `emails[something we have never seen].value` is treated as a
     * secondary address and left alone, exactly as it was before this server had a
     * filter parser.
     */
    private static function unparsableIsTolerated(string $path): bool
    {
        if (preg_match('/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*\[/', $path, $m) !== 1) {
            return false;
        }

        $attribute = strtolower($m[1]);

        return $attribute === 'emails' || in_array($attribute, self::TOLERATED_MULTI_VALUED, true);
    }

    /**
     * Whether a value filter on `emails` selects the address this server stores.
     *
     * This server keeps ONE email, it is the identifier somebody signs in with, and it is
     * returned as the primary. It is therefore modelled, for the purpose of a value
     * filter, as `{type: "work", primary: true, value: <the address>}`: a filter naming
     * `work` or `primary` — or the current address itself — selects it; one naming
     * `home` or `other` names a secondary address this server does not model and must
     * not be written over the login. The filter is EVALUATED (RFC 7644 §3.5.2), so
     * `emails[type eq "work" and primary eq true]` and `emails[type EQ "work"]` mean what
     * they say, and `emails[type eq "home"]` does not slip through.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function selectsStoredEmail(ScimPatchPath $path, array $attributes): bool
    {
        if ($path->filter === null) {
            return true;
        }

        return (new ScimFilterEvaluator)->matches($path->filter, [
            'type' => 'work',
            'primary' => true,
            'value' => self::nullableStr($attributes['email'] ?? null),
        ]);
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
    private static function setPath(array &$attributes, string $path, mixed $value, array &$touched): bool
    {
        // The whole extension as one nested object — the pathless spelling
        // `{"urn:…:enterprise:2.0:User": {"department": "…"}}`.
        if (strcasecmp(trim($path), self::ENTERPRISE_URN) === 0) {
            if (! is_array($value)) {
                return false;
            }

            $enterprise = is_array($attributes['enterprise'] ?? null) ? $attributes['enterprise'] : [];
            $attributes['enterprise'] = self::normalizeEnterprise(array_merge($enterprise, self::enterpriseKeys($value)));
            $touched[] = 'enterprise';

            return true;
        }

        $parsed = self::parsePath($path);

        if ($parsed === null) {
            return self::unparsableIsTolerated($path);
        }

        [$schema, $parsed] = $parsed;

        if ($schema === 'enterprise') {
            return self::setEnterprise($attributes, $parsed, $value, $touched);
        }

        if ($schema !== 'core') {
            return false;
        }

        if ($parsed->filter !== null) {
            return self::setFiltered($attributes, $parsed, $value, $touched);
        }

        $canonical = self::target($parsed);

        switch ($canonical) {
            case 'active':
                // Strict, never coercive: FILTER_VALIDATE_BOOLEAN answered false for any
                // value it did not recognise, so `"active": "fasle"` deactivated the
                // subject, dropped membership and revoked every session — and the IdP
                // recorded it as a successful write. Entra's `"False"` is still a boolean.
                $attributes['active'] = ScimBoolean::parse($value)
                    ?? throw InvalidScimRequest::notABoolean('active');
                break;
            case 'username':
                $attributes['userName'] = self::str($value);
                break;
            case 'externalid':
                // externalId is this directory's provisioning key: the row, the linked
                // subject and its federated identity are all keyed by it. Re-keying it
                // in place would orphan all three, so it is immutable here — the same
                // rule PUT applies. Writing the value it already has is not a change.
                if (self::str($value) !== self::str($attributes['externalId'] ?? null)) {
                    throw new InvalidScimRequest('externalId cannot be changed once provisioned; it is this directory\'s provisioning key.', 'mutability');
                }

                return true;
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
     * An `add`/`replace` that selects values with a filter.
     *
     * ONLY WHEN THE FILTER SELECTS THE SIGN-IN ADDRESS is anything written. This server
     * stores ONE email and it is the identifier somebody signs in with. An IdP mapping
     * that syncs a personal address as `emails[type eq "home"].value` used to be
     * indistinguishable from the work one once the filter was stripped, and replaced the
     * person's login with it. A secondary address is not refused either — a 400 fails
     * the WHOLE patch (RFC 7644 §3.5.2 is atomic) and would break every sync for every
     * user who happens to have one. It is simply not something this server stores.
     *
     * @param  array<string, mixed>  $attributes
     * @param  list<string>  $touched
     */
    private static function setFiltered(array &$attributes, ScimPatchPath $path, mixed $value, array &$touched): bool
    {
        $attribute = strtolower($path->attribute->attribute);

        if ($attribute === 'emails') {
            // `.type`, `.primary`, `.display` of the selected address are not stored
            // separately; the address is the only thing to write.
            if (! in_array($path->subAttribute === null ? null : strtolower($path->subAttribute), [null, 'value'], true)) {
                return true;
            }

            if (! self::selectsStoredEmail($path, $attributes)) {
                return true;
            }

            $attributes['email'] = is_array($value) && ! array_is_list($value)
                ? self::nullableStr(ScimAttributes::value($value, 'value'))
                : self::extractEmail($value);
            $touched[] = 'emails';

            return true;
        }

        return in_array($attribute, self::TOLERATED_MULTI_VALUED, true);
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
            if (! self::setPath($attributes, $path.'.'.$key, $sub, $touched)) {
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
     * cannot interpret at all. A sub-attribute of a tolerated multi-valued attribute
     * (`addresses.streetAddress`) is tolerated with it.
     */
    private static function isTolerated(string $canonicalPath): bool
    {
        $base = explode('.', $canonicalPath, 2)[0];

        if (in_array($base, self::TOLERATED_MULTI_VALUED, true)) {
            return true;
        }

        return in_array($canonicalPath, [
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
     * Write one Enterprise User attribute: `urn:…:enterprise:2.0:User:department`,
     * `…:User:manager`, `…:User:manager.value`, or the unqualified `manager` Entra sends.
     *
     * Every attribute of RFC 7643 §4.3 is stored; anything else under the URN is not
     * part of the extension at all and is refused. Previously every unsupported
     * attribute returned 200 and was then silently dropped — the IdP recorded a write
     * that never happened.
     *
     * @param  array<string, mixed>  $attributes
     * @param  list<string>  $touched
     */
    private static function setEnterprise(array &$attributes, ScimPatchPath $path, mixed $value, array &$touched): bool
    {
        $name = self::ENTERPRISE_NAMES[strtolower($path->attribute->attribute)] ?? null;
        $sub = $path->attribute->subAttribute ?? $path->subAttribute;

        // The extension's attributes are all single-valued: a value filter selects nothing.
        if ($name === null || $path->filter !== null) {
            return false;
        }

        $enterprise = is_array($attributes['enterprise'] ?? null) ? $attributes['enterprise'] : [];

        if ($sub !== null) {
            $field = self::MANAGER_FIELDS[strtolower($sub)] ?? null;

            if ($name !== 'manager' || $field === null) {
                return false;
            }

            $manager = self::normalizeManager($enterprise['manager'] ?? null) ?? [];
            $manager[$field] = $value;
            $enterprise['manager'] = $manager;
        } else {
            $enterprise[$name] = $value;
        }

        $attributes['enterprise'] = self::normalizeEnterprise($enterprise);
        $touched[] = 'enterprise.'.strtolower($name);

        return true;
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private static function removeEnterprise(array &$attributes, ScimPatchPath $path): bool
    {
        $name = self::ENTERPRISE_NAMES[strtolower($path->attribute->attribute)] ?? null;
        $sub = $path->attribute->subAttribute ?? $path->subAttribute;

        if ($name === null || $path->filter !== null) {
            return false;
        }

        $enterprise = is_array($attributes['enterprise'] ?? null) ? $attributes['enterprise'] : [];

        if ($sub === null) {
            unset($enterprise[$name]);
        } elseif ($name === 'manager' && isset(self::MANAGER_FIELDS[strtolower($sub)])) {
            $manager = self::normalizeManager($enterprise['manager'] ?? null) ?? [];
            unset($manager[self::MANAGER_FIELDS[strtolower($sub)]]);
            $enterprise['manager'] = $manager;
        } else {
            return false;
        }

        $attributes['enterprise'] = self::normalizeEnterprise($enterprise);

        return true;
    }

    /**
     * Re-key an Enterprise object onto the canonical attribute spellings, so
     * `{"Department": "x"}` is `department` (RFC 7643 §2.1).
     *
     * @param  array<array-key, mixed>  $value
     * @return array<string, mixed>
     */
    private static function enterpriseKeys(array $value): array
    {
        $out = [];

        foreach ($value as $key => $item) {
            $name = self::ENTERPRISE_NAMES[strtolower((string) $key)] ?? null;

            if ($name !== null) {
                $out[$name] = $item;
            }
        }

        return $out;
    }

    /**
     * The Enterprise `manager` as the complex attribute RFC 7643 §4.3 defines —
     * `{value, $ref, displayName}` — from any of the shapes identity providers send it
     * in: that object; a bare id string; or, from Microsoft Entra ID, a one-element list
     * of that object (`"value": [{"$ref": "…", "value": "…"}]`). Null when nothing usable
     * is left.
     *
     * @return array<string, mixed>|null
     */
    private static function normalizeManager(mixed $value): ?array
    {
        if (is_string($value)) {
            return $value === '' ? null : ['value' => $value];
        }

        if (! is_array($value)) {
            return null;
        }

        if (array_is_list($value)) {
            return self::normalizeManager($value[0] ?? null);
        }

        $manager = [];

        foreach ($value as $key => $item) {
            $field = self::MANAGER_FIELDS[strtolower((string) $key)] ?? null;

            if ($field !== null && is_string($item) && $item !== '') {
                $manager[$field] = $item;
            }
        }

        return $manager === [] ? null : $manager;
    }

    /**
     * A top-level body member matched without regard to case — never as a dot path.
     *
     * @param  array<array-key, mixed>  $body
     */
    private static function topLevel(array $body, string $name): mixed
    {
        foreach ($body as $key => $value) {
            if (strcasecmp((string) $key, $name) === 0) {
                return $value;
            }
        }

        return null;
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

            if ($key === 'manager') {
                // Always the complex attribute RFC 7643 §4.3 defines, never a bare id —
                // a schema-violating string here broke the IdP's own read-back.
                $manager = self::normalizeManager($value[$key]);

                if ($manager !== null) {
                    $out[$key] = $manager;
                }

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
     * The resource's weak entity-tag (RFC 7644 §3.14) — `meta.version` and the `ETag`
     * header both.
     */
    public static function version(DirectoryUser $directoryUser): string
    {
        $revision = $directoryUser->getAttribute('version');

        return ScimETag::forRevision($directoryUser->id, is_int($revision) ? $revision : 1);
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
                self::version($directoryUser),
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
