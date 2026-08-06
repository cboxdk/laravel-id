<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Contracts;

use Cbox\Id\Kernel\Events\ValueObjects\BacklogDepth;

/**
 * How far behind the domain-event relay is.
 *
 * Relay lag used to be completely silent: nothing reported how many outbox rows
 * were waiting, so a stalled relay looked identical to an idle one right up until
 * a customer noticed missing webhooks. This is the signal.
 *
 * It is a CONTRACT rather than a metrics call on purpose. `cboxdk/laravel-id` is
 * a dependency-light framework package and must not force a telemetry runtime on
 * its host (`cboxdk/laravel-telemetry` is not — and should not become — a
 * dependency of this library). A host that has telemetry resolves this and feeds
 * its own gauge; a host that doesn't can run `cbox-id:events:backlog`.
 */
interface RelayBacklog
{
    public function depth(): BacklogDepth;
}
