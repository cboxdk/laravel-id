<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A federated identity link: (provider, subject) → user. One user may have many.
 *
 * @property string $id
 * @property string $user_id
 * @property string $provider
 * @property string $subject
 * @property string|null $connection_id
 * @property array<string, mixed> $raw
 */
final class IdentityLink extends Model
{
    use HasUlids;

    protected $table = 'identities';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'raw' => 'array',
        ];
    }
}
