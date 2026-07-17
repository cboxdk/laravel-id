<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

/**
 * How a directory's users arrive. `Scim` is push (the customer's IdP posts SCIM to
 * us); the rest are API-pull connectors (we fetch from the provider on a schedule).
 * Pull covers directories with no SCIM support (Google Workspace) and those where
 * a customer prefers pull (Entra also supports SCIM push, but many want pull).
 */
enum DirectoryProvider: string
{
    case Scim = 'scim';
    case GoogleWorkspace = 'google_workspace';
    case MicrosoftEntra = 'microsoft_entra';

    public function label(): string
    {
        return match ($this) {
            self::Scim => 'SCIM (push)',
            self::GoogleWorkspace => 'Google Workspace',
            self::MicrosoftEntra => 'Microsoft Entra ID',
        };
    }

    /** Whether this provider is synced by pulling from its API (vs. SCIM push). */
    public function isPull(): bool
    {
        return $this !== self::Scim;
    }
}
