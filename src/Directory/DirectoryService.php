<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\PullDirectories;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Enums\DirectoryStatus;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\ValueObjects\RegisteredDirectory;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Support\OwnerEnvironment;

class DirectoryService implements Directories, PullDirectories
{
    public function __construct(private readonly SecretBox $secretBox) {}

    public function registerPull(string $organizationId, string $name, DirectoryProvider $provider, array $credentials): Directory
    {
        // Same reason as every other writer of an `organization_id`: the environment stamp
        // and the named owner are written side by side and nothing checks they agree.
        OwnerEnvironment::assertLocal($organizationId, Directory::class);

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
        OwnerEnvironment::assertLocal($organizationId, Directory::class);

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

    public function replaceCredentials(Directory $directory, array $credentials): Directory
    {
        if (! $directory->provider->isPull()) {
            throw DirectoryConnectionFailed::make($directory->provider->label(), 'A SCIM directory has no provider credentials; rotate its bearer token instead.');
        }

        $directory->forceFill([
            'credentials' => $this->secretBox->seal(
                (string) json_encode($credentials),
                'cbox-id:directory-credentials:'.$directory->id,
            ),
            // New credentials are a new conversation with the provider: the next run is a
            // full pull, and the last run's complaint about the old credentials is history.
            'sync_cursor' => null,
            'last_sync_error' => null,
        ])->save();

        return $directory;
    }

    public function setSyncInterval(Directory $directory, ?int $minutes): Directory
    {
        $directory->forceFill([
            'sync_interval_minutes' => $minutes === null
                ? null
                : max(Directory::MIN_SYNC_INTERVAL_MINUTES, min(Directory::MAX_SYNC_INTERVAL_MINUTES, $minutes)),
        ])->save();

        return $directory;
    }

    public function setHrisOptions(Directory $directory, array $customAttributes, array $fieldMap = []): Directory
    {
        $mappings = $directory->mappings ?? [];

        $custom = array_values(array_unique(array_filter(
            array_map(static fn (string $name): string => trim($name), $customAttributes),
            static fn (string $name): bool => $name !== '',
        )));

        $map = [];

        foreach ($fieldMap as $ours => $theirs) {
            if (trim($theirs) !== '') {
                $map[$ours] = trim($theirs);
            }
        }

        $mappings['hris'] = ['custom_attributes' => $custom, 'field_map' => $map];

        // A different set of fields is a different answer for everybody: pull them all.
        $directory->forceFill(['mappings' => $mappings, 'sync_cursor' => null])->save();

        return $directory;
    }
}
