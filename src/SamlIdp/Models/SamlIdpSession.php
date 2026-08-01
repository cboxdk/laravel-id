<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One assertion we issued: which subject, to which service provider, under what NameID.
 *
 * Single Logout needs this and had nothing. It took the NameID out of a signed
 * LogoutRequest, resolved it as a subject id or an email, and revoked every session that
 * person had — so any registered SP could name any user (an email is not a secret) and
 * end their day, repeatedly, over users it had never seen.
 *
 * Environment-owned, because a NameID is only meaningful inside the environment that
 * issued it and an SP EntityID is not globally unique.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $sp_entity_id
 * @property string $subject_id
 * @property string $name_id
 * @property string $session_index
 * @property Carbon|null $expires_at
 */
class SamlIdpSession extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_idp_sessions';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }
}
