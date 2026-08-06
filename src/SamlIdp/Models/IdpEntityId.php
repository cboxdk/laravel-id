<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The IdP EntityID this environment has published, frozen at first use.
 *
 * An EntityID is an opaque, PERMANENT name for a SAML entity: every SP that
 * federates to us stores it and rejects any assertion whose Issuer differs. It is
 * derived from the environment's issuer, which follows the host — so without this
 * row, verifying a custom domain changed the EntityID underneath every SP at once
 * ({@see IdpDescriptor::entityId()} explains the read side). The endpoint URLs
 * still follow the host; only the name is pinned.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $entity_id
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class IdpEntityId extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_idp_entity_ids';

    protected $guarded = [];
}
