<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

/**
 * The input to self-serve account provisioning: the workspace to create, its
 * first member (who signs in at the platform root), and the first environment to
 * stand up under it.
 *
 * Note what is NOT here: no organization, no end-user. A freshly provisioned
 * environment starts empty of tenants — the member administers it from the root
 * console. Organizations and their users are created later, inside the
 * environment, which is exactly the Account → Environment → Organization → User
 * layering (the account plane never seeds the end-user plane).
 */
readonly class AccountBlueprint
{
    public function __construct(
        public string $accountName,
        public string $ownerEmail,
        public ?string $ownerName,
        public string $ownerPassword,
        public string $environmentName = 'Production',
        public ?string $domain = null,
        public int $environmentLimit = 2,
    ) {}
}
