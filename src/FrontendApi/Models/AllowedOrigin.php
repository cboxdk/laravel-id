<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One serialized origin — `scheme://host[:port]` — that may use a publishable key.
 *
 * NOT environment-owned in its own right: it hangs off the key, and the key carries the
 * environment. A second scope here would be a second answer to the same question, which
 * is how a row ends up reachable through one path and invisible through another.
 *
 * @property string $id
 * @property string $frontend_api_key_id
 * @property string $origin
 */
class AllowedOrigin extends Model
{
    use HasUlids;

    protected $table = 'frontend_api_origins';

    protected $guarded = [];

    /** @return BelongsTo<PublishableKey, $this> */
    public function key(): BelongsTo
    {
        return $this->belongsTo(PublishableKey::class, 'frontend_api_key_id');
    }
}
