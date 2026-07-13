<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A machine identity (M2M), backed by a confidential client.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $name
 * @property string $client_id
 * @property string|null $rotated_from
 * @property string $status
 * @property Carbon|null $retired_at
 */
final class ServiceAccount extends Model
{
    use HasUlids;

    protected $table = 'oauth_service_accounts';

    protected $guarded = [];
}
