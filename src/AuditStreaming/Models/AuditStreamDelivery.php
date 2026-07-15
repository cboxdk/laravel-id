<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\LaravelSiem\Models\StreamDelivery;

/**
 * An environment-owned outbox row. Pointed at by
 * `config('siem.models.stream_delivery')`, so the transactional-outbox insert the
 * dispatcher performs is auto-stamped with the current environment, and the pump's
 * claim query only ever sees rows for the environment it is running inside. An
 * env-A audit entry can therefore only ever produce (and be delivered from) an
 * env-A delivery row — the cross-environment path is closed structurally, not by
 * remembering to add a `where`.
 *
 * @property string $environment_id
 */
class AuditStreamDelivery extends StreamDelivery implements EnvironmentOwned
{
    use BelongsToEnvironment;
}
