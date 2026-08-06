<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Testing;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\ValueObjects\DirectoryGroupSnapshot;
use Cbox\Id\Directory\ValueObjects\ScimUser;

/**
 * A controllable pull connector for testing sync orchestration without a real
 * provider — set the users/groups it returns, and flip {@see $verifies}.
 */
class FakeDirectoryConnector implements DirectoryConnector
{
    /**
     * @param  list<ScimUser>  $users
     * @param  list<DirectoryGroupSnapshot>  $groups
     */
    public function __construct(
        private readonly DirectoryProvider $provider = DirectoryProvider::GoogleWorkspace,
        private array $users = [],
        private array $groups = [],
        public bool $verifies = true,
    ) {}

    /**
     * @param  list<ScimUser>  $users
     */
    public function returns(array $users): self
    {
        $this->users = $users;

        return $this;
    }

    /**
     * @param  list<DirectoryGroupSnapshot>  $groups
     */
    public function returnsGroups(array $groups): self
    {
        $this->groups = $groups;

        return $this;
    }

    public function provider(): DirectoryProvider
    {
        return $this->provider;
    }

    public function fetchUsers(array $credentials): iterable
    {
        return $this->users;
    }

    public function fetchGroups(array $credentials): iterable
    {
        return $this->groups;
    }

    public function verify(array $credentials): bool
    {
        return $this->verifies;
    }
}
