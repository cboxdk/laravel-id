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
 * @property string $id
 * @property string $jti
 * @property Carbon $expires_at
 */
final class DpopProof extends Model
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
