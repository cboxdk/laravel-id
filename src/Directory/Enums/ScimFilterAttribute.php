<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

/**
 * The `/Users` attributes this server accepts in a SCIM filter, each bound to the
 * column it targets and the {@see ScimValueType} that governs its comparison.
 *
 * Closed by design: an attribute that is not a case here is refused with
 * `invalidFilter` rather than silently matching nothing, so an IdP learns its query
 * was not understood instead of concluding the directory is empty.
 */
enum ScimFilterAttribute: string
{
    case UserName = 'username';
    case ExternalId = 'externalid';
    case Active = 'active';
    case Emails = 'emails';
    case EmailsValue = 'emails.value';
    case LastModified = 'meta.lastmodified';
    case Created = 'meta.created';

    /**
     * SCIM attribute names are case-insensitive (RFC 7643 §2.1).
     */
    public static function tryParse(string $attribute): ?self
    {
        return self::tryFrom(strtolower($attribute));
    }

    /**
     * The `directory_users` column this attribute is stored in. `userName` and the
     * primary email resolve to their pre-folded comparison columns, not the JSON blob —
     * matching inside the blob made equality depend on the database's collation.
     */
    public function column(): string
    {
        return match ($this) {
            self::UserName => 'user_name_lower',
            self::ExternalId => 'external_id',
            self::Active => 'active',
            self::Emails, self::EmailsValue => 'email_lower',
            self::LastModified => 'updated_at',
            self::Created => 'created_at',
        };
    }

    public function type(): ScimValueType
    {
        return match ($this) {
            // RFC 7643 §4.1.1 marks both `caseExact: false`.
            self::UserName, self::Emails, self::EmailsValue => ScimValueType::CaseInsensitiveText,
            // Client-assigned and opaque: compared exactly as the IdP issued it.
            self::ExternalId => ScimValueType::CaseSensitiveText,
            self::Active => ScimValueType::Boolean,
            self::LastModified, self::Created => ScimValueType::Timestamp,
        };
    }
}
