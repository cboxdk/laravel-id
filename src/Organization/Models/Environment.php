<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment as EnvironmentContract;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * The environment — the hard identity/tenancy boundary. It is NOT itself
 * environment-owned (it is the boundary); provisioning it happens outside any
 * environment scope. Its id is the environment key stored on every owned row.
 *
 * @property string $id
 * @property string $name
 * @property string $slug
 * @property string $status
 * @property array<string, mixed> $settings
 */
final class Environment extends Model implements EnvironmentContract
{
    use HasUlids;

    protected $table = 'environments';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['settings' => 'array'];
    }

    public function environmentKey(): string
    {
        return $this->id;
    }
}
