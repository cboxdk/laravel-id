<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Models;

use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A platform signing key. Global (not tenant-owned): the platform is the single
 * token issuer. The private key is stored sealed and never leaves this row in
 * cleartext.
 *
 * @property string $id
 * @property string $kid
 * @property SigningAlg $alg
 * @property string $public_key
 * @property string $private_key_encrypted
 * @property KeyStatus $status
 * @property Carbon|null $activated_at
 * @property Carbon|null $retired_at
 */
final class SigningKey extends Model
{
    use HasUlids;

    protected $table = 'signing_keys';

    protected $guarded = [];

    /**
     * The additional-authenticated-data context binding this key's ciphertext
     * to this specific key id.
     */
    public function secretContext(): string
    {
        return 'cbox-id:signing-key:'.$this->kid;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'alg' => SigningAlg::class,
            'status' => KeyStatus::class,
            'activated_at' => 'datetime',
            'retired_at' => 'datetime',
        ];
    }
}
