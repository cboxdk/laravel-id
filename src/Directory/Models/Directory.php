<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Directory\Enums\DirectoryStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A per-org SCIM directory connection. The bearer token (used by the customer's
 * IdP to authenticate SCIM calls) is stored only as a SHA-256 hash.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $name
 * @property string $bearer_token_hash
 * @property DirectoryStatus $status
 * @property array<string, mixed> $mappings
 */
final class Directory extends Model
{
    use HasUlids;

    protected $table = 'directories';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => DirectoryStatus::class,
            'mappings' => 'array',
        ];
    }
}
