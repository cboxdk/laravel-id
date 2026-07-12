<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A registered passkey / WebAuthn credential. `sign_count` is the authenticator's
 * monotonic counter — it must strictly increase across assertions; a non-increase
 * flags a possibly cloned authenticator.
 *
 * @property string $id
 * @property string $user_id
 * @property string $credential_id
 * @property string $public_key
 * @property int $sign_count
 * @property array<int, string> $transports
 * @property string|null $name
 */
final class WebAuthnCredential extends Model
{
    use HasUlids;

    protected $table = 'webauthn_credentials';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sign_count' => 'integer',
            'transports' => 'array',
        ];
    }
}
