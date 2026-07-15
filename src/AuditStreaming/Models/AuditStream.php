<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Cbox\LaravelSiem\Models\LogStream;

/**
 * An environment-owned {@see LogStream}. This is the one line that gives the whole
 * SIEM delivery engine its isolation for free: by pointing
 * `config('siem.models.log_stream')` at this subclass, EVERY read/list/create the
 * engine performs (registry, dispatcher, pump) flows through the hard
 * {@see EnvironmentScope} — deny-by-default, so a
 * query with no ambient environment matches zero rows, and a write is stamped and
 * fenced to the current environment.
 *
 * The base model is deliberately tenancy-agnostic (its `owner_key` seam is left
 * unused here); the `environment_id` column added by this package's migration is
 * the authoritative boundary. Casts, ULID keys and `$guarded = []` are inherited
 * from {@see LogStream}, so nothing about the engine's own schema is re-declared.
 *
 * @property string $environment_id
 */
class AuditStream extends LogStream implements EnvironmentOwned
{
    use BelongsToEnvironment;
}
