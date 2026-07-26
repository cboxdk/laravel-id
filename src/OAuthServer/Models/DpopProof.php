<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A consumed DPoP proof id, kept until the proof's freshness window closes so the
 * same proof cannot be replayed (RFC 9449 §11.1).
 *
 * The replay key is `(jkt, jti)` — the proof's key thumbprint plus its nonce — not
 * `jti` alone, because `jti` is client-chosen and only required to be unique per key.
 *
 * Deliberately NOT an `EnvironmentOwned` model despite carrying `environment_id`:
 * nothing ever SELECTs from this table (the replay guard is the unique constraint on
 * insert, and the sweep runs unscoped), so a hard scope would add a filter no read
 * needs while making the write fail on the platform plane, which legitimately has no
 * environment. The column is stamped explicitly by the validator.
 *
 * @property string $id
 * @property string|null $environment_id
 * @property string $jkt
 * @property string $jti
 * @property Carbon $expires_at
 */
class DpopProof extends Model
{
    use HasUlids;

    protected $table = 'dpop_proofs';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }
}
