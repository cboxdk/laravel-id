<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\Models\AccountMember;

/**
 * The result of provisioning a new account: the workspace, its first member (the
 * root-console login), and its first environment — an empty, routable IdP realm
 * ready for the member to configure.
 */
final readonly class ProvisionedAccount
{
    public function __construct(
        public Account $account,
        public AccountMember $member,
        public Environment $environment,
    ) {}
}
