<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Enums;

/**
 * The heading a {@see WebhookEventType} sits under in a subscription picker or a docs
 * page. Declaration order is display order.
 */
enum WebhookEventGroup: string
{
    case Users = 'users';
    case Organizations = 'organizations';
    case Memberships = 'memberships';
    case Invitations = 'invitations';
    case Roles = 'roles';
    case ApiKeys = 'api_keys';
    case Support = 'support';
    case Directory = 'directory';
    case Domains = 'domains';
    case Connections = 'connections';
    case Entitlements = 'entitlements';
    case TokenVault = 'token_vault';
    case Governance = 'governance';

    public function label(): string
    {
        return match ($this) {
            self::Users => 'Users',
            self::Organizations => 'Organizations',
            self::Memberships => 'Memberships',
            self::Invitations => 'Invitations',
            self::Roles => 'Roles',
            self::ApiKeys => 'API keys',
            self::Support => 'Support access',
            self::Directory => 'Directory sync (SCIM)',
            self::Domains => 'Domains',
            self::Connections => 'SSO connections',
            self::Entitlements => 'Entitlements',
            self::TokenVault => 'Token vault',
            self::Governance => 'Access governance',
        };
    }
}
