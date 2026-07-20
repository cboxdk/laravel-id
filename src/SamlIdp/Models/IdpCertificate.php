<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Models;

use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The self-signed X.509 certificate wrapping the platform's active RSA signing
 * key, keyed by that key's `kid`. The IdP reuses the one platform signing key so
 * metadata, JWKS and SAML all present a single identity — there is no second key
 * store. The certificate is public material (it is published in metadata); only
 * the private key stays sealed in {@see SigningKey}.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $kid
 * @property string $certificate
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class IdpCertificate extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_idp_certificates';

    protected $guarded = [];
}
