<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Enums\DirectoryStatus;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\ValueObjects\RegisteredDirectory;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;

class DirectoryService implements Directories
{
    public function __construct(private readonly SecretBox $secretBox) {}

    public function registerPull(string $organizationId, string $name, DirectoryProvider $provider, array $credentials): Directory
    {
        $directory = new Directory;
        $directory->fill([
            'organization_id' => $organizationId,
            'name' => $name,
            'provider' => $provider,
            // A pull directory has no inbound token; a random unused hash satisfies
            // the unique + non-null column and is never matched by a presented token.
            'bearer_token_hash' => hash('sha256', 'pull_'.bin2hex(random_bytes(32))),
            'status' => DirectoryStatus::Active,
            'mappings' => [],
        ]);
        $directory->save();

        // Seal the credentials bound to the (now-known) directory id.
        $directory->forceFill([
            'credentials' => $this->secretBox->seal(
                (string) json_encode($credentials),
                'cbox-id:directory-credentials:'.$directory->id,
            ),
        ])->save();

        return $directory;
    }

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
