<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Platform\Enums\OperatorStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A platform operator — an identity above every environment. It is deliberately
 * NOT environment-owned (no {@see BelongsToEnvironment}):
 * an operator authenticates once at the platform level and can then assume any
 * environment's console. Data it creates lands in whichever environment is
 * pinned for the request; the operator record itself lives above them all.
 *
 * @property string $id
 * @property string $email
 * @property string|null $name
 * @property string $password
 * @property OperatorStatus $status
 * @property Carbon|null $last_login_at
 */
class PlatformOperator extends Model
{
    use HasUlids;

    protected $table = 'platform_operators';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['password'];

    public function isActive(): bool
    {
        return $this->status === OperatorStatus::Active;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => OperatorStatus::class,
            'password' => 'hashed',
            'last_login_at' => 'datetime',
        ];
    }
}
