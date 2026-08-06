<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

/**
 * How a directory's users arrive. `Scim` is push (the customer's IdP posts SCIM to
 * us); the rest are API-pull connectors (we fetch from the provider on a schedule).
 * Pull covers directories with no SCIM support (Google Workspace) and those where
 * a customer prefers pull (Entra also supports SCIM push, but many want pull).
 *
 * **This enum is a persistence type, not a catalogue.** It is what sits in
 * `directories.provider` on every row ever written, what the connector registry is keyed
 * by, and what the sync command filters on — a serialization boundary, and the one place
 * where a rename is a migration rather than an edit. The provider METADATA it used to
 * imply — what the thing is called, how to set it up, where its documentation is — now
 * lives once in the provider catalogue, reached via `ProviderCatalog::forDirectory()`.
 * Folding this enum away into the catalogue would have bought nothing and cost a
 * migration over stored rows.
 *
 * Named in prose rather than imported on purpose: nothing in this module depends on
 * Federation, and it must stay that way. The catalogue reaches down to this enum, the
 * sync path never reaches up, and a host that renders no setup screen at all still syncs.
 *
 * {@see self::label()} stays because `Scim` has no catalogue entry and never will (it is
 * a protocol spoken TO us, not a service we connect to), and because a stored row must
 * still render when no entry exists for it. A screen that has the catalogue should prefer
 * the catalogue's name.
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
