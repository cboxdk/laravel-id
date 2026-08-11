<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Models;

use Carbon\CarbonInterface;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Where an app said its old login lives, and whether a person has agreed to it.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $client_id
 * @property string $url
 * @property string $secret_encrypted
 * @property CarbonInterface|null $approved_at
 * @property string|null $approved_by
 */
class LegacyLoginDeclarationRecord extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'legacy_login_declarations';

    protected $guarded = [];

    /**
     * Whether this declaration is actually in the sign-in path.
     *
     * The whole point of the column: a declaration exists the moment an app pushes its
     * manifest, and does nothing until somebody looks at it. See the migration for why
     * this one thing an app declares needs a human in the loop when its roles do not.
     */
    public function isApproved(): bool
    {
        return $this->approved_at !== null;
    }

    /** The same shape as every other sealed secret here, so nothing has to guess. */
    public function secretContext(): string
    {
        return 'cbox-id:legacy-login:'.$this->id;
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['approved_at' => 'datetime'];
    }
}
