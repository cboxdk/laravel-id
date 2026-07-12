<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Enums\DirectoryStatus;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\ValueObjects\RegisteredDirectory;

final class DirectoryService implements Directories
{
    public function register(string $organizationId, string $name): RegisteredDirectory
    {
        $token = 'scim_'.bin2hex(random_bytes(32));

        $directory = new Directory;
        $directory->fill([
            'organization_id' => $organizationId,
            'name' => $name,
            'bearer_token_hash' => hash('sha256', $token),
            'status' => DirectoryStatus::Active,
            'mappings' => [],
        ]);
        $directory->save();

        return new RegisteredDirectory($directory, $token);
    }

    public function authenticate(string $token): ?Directory
    {
        return Directory::query()
            ->where('bearer_token_hash', hash('sha256', $token))
            ->where('status', DirectoryStatus::Active->value)
            ->first();
    }
}
