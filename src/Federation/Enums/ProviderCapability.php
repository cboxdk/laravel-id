<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;

/**
 * What a catalogue provider can be used FOR.
 *
 * Google is one provider. An organization connects it to let people sign in, and it
 * connects it again to keep the user list in step — two different acts, two different
 * credentials, one company an administrator already knows how to talk to. Before this
 * enum those two facts lived in unrelated registries that shared nothing but a name, so
 * the directory screen could not show the guide the catalogue already held for the same
 * provider, and an administrator who had just finished connecting Google for sign-in got
 * no help at all connecting Google as a directory.
 *
 * A capability is not a permission and not a feature flag. It is the answer to "is there
 * anything in this entry that would let me set this up?", which is why it is DERIVED from
 * the entry's contents rather than declared beside them — see
 * {@see ProviderTemplate::capabilities()}. A declared list is a claim that can be false;
 * a derived one cannot offer a provider the console has no way to finish setting up.
 */
enum ProviderCapability: string
{
    /** People authenticate with this provider: OIDC discovery or fixed OAuth 2.0 endpoints. */
    case Login = 'login';

    /**
     * We read this provider's user list on a schedule.
     *
     * Only API-pull directories are ever this. SCIM is push and is deliberately not a
     * catalogue provider at all — see {@see ProviderCatalog}.
     */
    case Directory = 'directory';

    public function label(): string
    {
        return match ($this) {
            self::Login => 'Sign-in',
            self::Directory => 'User sync',
        };
    }
}
