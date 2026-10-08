<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Directory\Enums\ScimAttributeType;
use Cbox\Id\Scim\Filter\AttributePath;
use Cbox\Id\Scim\ScimSchema;

/**
 * The closed set of attributes a directory resource can be filtered and sorted on
 * (RFC 7644 §3.4.2.2, §3.4.2.3), and how each one maps onto the store.
 *
 * ## Name resolution
 *
 * RFC 7644 §3.10: clients "MAY omit core schema attribute URN prefixes but SHOULD fully
 * qualify extension attributes". So a path qualified with the resource's core schema
 * URN, or not qualified at all, resolves against the core attributes; one qualified with
 * the Enterprise User URN resolves against the extension; and an UNQUALIFIED name the
 * core schema does not define falls back to the extension — Microsoft Entra ID checks a
 * user's manager with a bare `manager eq "…"`. Any other URN resolves to nothing.
 *
 * A complex attribute named without a sub-attribute means its `value`
 * (`emails eq "x"` is `emails.value eq "x"`, `manager eq "x"` is `manager.value`).
 *
 * ## The stored email
 *
 * The directory keeps ONE address per user and returns it as the primary. PATCH has
 * always treated `emails[type eq "work"]` and `emails[primary eq true]` as naming it;
 * filters do the same, so `emails[type eq "work"].value eq "x"` — the form Entra uses
 * when uniqueness is keyed on the work email — finds the user. `emails.type` and
 * `emails.primary` are therefore constants of the stored address, not stored values.
 */
class ScimQueryAttributes
{
    /**
     * @param  array<string, ScimQueryAttribute>  $core  keyed by canonical path
     * @param  array<string, ScimQueryAttribute>  $extension  keyed by canonical path
     */
    public function __construct(
        private readonly string $coreSchema,
        private readonly array $core,
        private readonly ?string $extensionSchema = null,
        private readonly array $extension = [],
    ) {}

    public static function users(): self
    {
        $ci = ScimAttributeType::CaseInsensitiveString;
        $exact = ScimAttributeType::CaseExactString;

        return new self(ScimSchema::USER_URN, [
            'id' => ScimQueryAttribute::column('id', $exact),
            'externalid' => ScimQueryAttribute::column('external_id', $exact),
            'username' => ScimQueryAttribute::column('user_name_lower', $ci, folded: true),
            'active' => ScimQueryAttribute::column('active', ScimAttributeType::Boolean),
            'displayname' => ScimQueryAttribute::json('displayName', 'displayName', $ci),
            'name.formatted' => ScimQueryAttribute::json('displayName', 'displayName', $ci),
            'name.givenname' => ScimQueryAttribute::json('givenName', 'givenName', $ci),
            'name.familyname' => ScimQueryAttribute::json('familyName', 'familyName', $ci),
            'emails' => ScimQueryAttribute::column('email_lower', $ci, folded: true),
            'emails.value' => ScimQueryAttribute::column('email_lower', $ci, folded: true),
            'emails.primary' => ScimQueryAttribute::constant(true, 'email_lower', ScimAttributeType::Boolean),
            'emails.type' => ScimQueryAttribute::constant('work', 'email_lower', $ci),
            'meta.created' => ScimQueryAttribute::column('created_at', ScimAttributeType::DateTime),
            'meta.lastmodified' => ScimQueryAttribute::column('updated_at', ScimAttributeType::DateTime),
        ], ScimSchema::ENTERPRISE_URN, [
            'employeenumber' => ScimQueryAttribute::json('enterprise.employeeNumber', 'enterprise,employeeNumber', $ci),
            'costcenter' => ScimQueryAttribute::json('enterprise.costCenter', 'enterprise,costCenter', $ci),
            'organization' => ScimQueryAttribute::json('enterprise.organization', 'enterprise,organization', $ci),
            'division' => ScimQueryAttribute::json('enterprise.division', 'enterprise,division', $ci),
            'department' => ScimQueryAttribute::json('enterprise.department', 'enterprise,department', $ci),
            'manager' => ScimQueryAttribute::json('enterprise.manager.value', 'enterprise,manager,value', $exact),
            'manager.value' => ScimQueryAttribute::json('enterprise.manager.value', 'enterprise,manager,value', $exact),
            'manager.displayname' => ScimQueryAttribute::json('enterprise.manager.displayName', 'enterprise,manager,displayName', $ci),
        ]);
    }

    public static function groups(): self
    {
        $ci = ScimAttributeType::CaseInsensitiveString;
        $exact = ScimAttributeType::CaseExactString;
        $members = ScimQueryAttribute::relation('members', self::members());

        return new self(ScimSchema::GROUP_URN, [
            'id' => ScimQueryAttribute::column('id', $exact),
            'externalid' => ScimQueryAttribute::column('external_id', $exact),
            'displayname' => ScimQueryAttribute::column('display_name', $ci),
            'members' => $members,
            'members.value' => $members,
            'members.display' => $members,
            'members.type' => $members,
            'meta.created' => ScimQueryAttribute::column('created_at', ScimAttributeType::DateTime),
            'meta.lastmodified' => ScimQueryAttribute::column('updated_at', ScimAttributeType::DateTime),
        ]);
    }

    /**
     * The sub-attributes of one group member (RFC 7643 §4.2), queried inside the
     * membership relation — so every column is table-qualified, because the pivot it
     * joins through has an `id` of its own.
     */
    public static function members(): self
    {
        return new self(ScimSchema::GROUP_URN, [
            'value' => ScimQueryAttribute::column('directory_users.id', ScimAttributeType::CaseExactString),
            'display' => ScimQueryAttribute::column('directory_users.user_name_lower', ScimAttributeType::CaseInsensitiveString, folded: true),
            'type' => ScimQueryAttribute::constant('User', 'directory_users.id', ScimAttributeType::CaseInsensitiveString),
        ]);
    }

    /**
     * The attribute a path names, or null when the store holds no such attribute.
     */
    public function resolve(AttributePath $path): ?ScimQueryAttribute
    {
        $name = $path->canonical();

        if ($path->schema === null) {
            return $this->core[$name] ?? $this->extension[$name] ?? null;
        }

        if ($path->inSchema($this->coreSchema)) {
            return $this->core[$name] ?? null;
        }

        if ($this->extensionSchema !== null && $path->inSchema($this->extensionSchema)) {
            return $this->extension[$name] ?? null;
        }

        return null;
    }
}
