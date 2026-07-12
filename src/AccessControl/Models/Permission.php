<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $name
 * @property string|null $description
 */
final class Permission extends Model
{
    use HasUlids;

    protected $table = 'permissions';

    protected $guarded = [];
}
