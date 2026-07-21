<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

class DatabaseEventBus implements EventBus
{
    public function __construct(
        private readonly Dispatcher $dispatcher,
        private readonly EnvironmentContext $environments,
        private readonly EnvironmentResolver $environmentResolver,
    ) {}

    public function emit(DomainEvent $event): Event
    {
        $row = new Event;
        $row->fill([
            'type' => $event->type,
            'organization_id' => $event->organizationId,
            // Stamp the ambient environment at emit — the relay flushes across
            // environments, so this is how a delivered event carries its origin
            // (the outbox row is deliberately NOT environment-scoped itself).
            'environment_id' => $this->environments->current()?->environmentKey(),
            'payload' => $event->payload,
            'occurred_at' => now(),
        ]);
        $row->save();

        return $row;
    }

    public function flushPending(int $limit = 100): int
    {
        $pending = $this->claim($limit);

        // Resolve each distinct environment ONCE per pass. A batch is usually one or
        // two environments, and forKey() is a query — resolving per event made the
        // relay an N+1 against a table that changes almost never.
        $environments = [];
        $delivered = 0;

        foreach ($pending as $event) {
            $key = $event->environment_id;

            if ($key !== null && ! array_key_exists($key, $environments)) {
                $environments[$key] = $this->environmentResolver->forKey($key);
            }

            $environment = $key !== null ? $environments[$key] : null;

            if ($key !== null && $environment === null) {
                // The environment row does not resolve (deleted, or never materialised).
                // Fall back to the KEY itself: the tenancy scope is the key string, and
                // the Environment record is only metadata about it — so scoping by key
                // still isolates listeners correctly. Dispatching unscoped instead would
                // run them against the wrong scope, where EnvironmentScope matches
                // nothing and the event is silently swallowed while looking delivered.
                $environment = GenericEnvironment::of($key);
                $environments[$key] = $environment;

                Log::notice('cbox-id: outbox event has no resolvable environment row; scoping by key.', [
                    'event_id' => $event->id,
                    'environment_id' => $key,
                    'type' => $event->type,
                ]);
            }

            // Dispatch INSIDE the event's own environment context. Listeners (e.g. the
            // webhook fan-out) resolve environment-scoped models, so flushing from a
            // scheduler/queue with no ambient context would otherwise match nothing —
            // or, worse, match a stale worker's environment. A platform (null-env)
            // event dispatches unscoped.
            try {
                if ($environment !== null) {
                    $this->environments->runAs($environment, fn () => $this->dispatcher->dispatch(new EventDelivered($event)));
                } else {
                    $this->dispatcher->dispatch(new EventDelivered($event));
                }
            } catch (Throwable $e) {
                // Isolate the failure. An uncaught listener throw used to abort the whole
                // pass: the rest of the claimed batch sat undelivered for the full reclaim
                // window, and the throwing event — whose earlier listeners HAD run — was
                // re-delivered on reclaim, reintroducing exactly the double-send this
                // design exists to prevent, forever, since nothing counted attempts.
                //
                // Release the claim so it retries promptly, and keep going.
                //
                // A query update, NOT $event->save(): the models were fetched BEFORE
                // claim() stamped claimed_at, so in memory it is already null and Eloquent
                // would see no change and write nothing — leaving the row claimed for the
                // whole reclaim window. (The test caught exactly that.)
                Event::query()->whereKey($event->id)->update(['claimed_at' => null]);

                Log::error('cbox-id: outbox event delivery failed; releasing the claim.', [
                    'event_id' => $event->id,
                    'type' => $event->type,
                    'reason' => $e->getMessage(),
                ]);

                continue;
            }

            $event->forceFill(['dispatched_at' => now()])->save();
            $delivered++;
        }

        return $delivered;
    }

    /**
     * Take exclusive ownership of a batch of pending events.
     *
     * Claiming and delivering are separated because two relays — an overlapping
     * scheduler tick, or two app instances — otherwise select the same rows and deliver
     * every event twice: every webhook sent twice, every usage counter double-counted.
     * The claim is a short transaction that touches no listeners, so it never holds a
     * row lock across an outbound HTTP call.
     *
     * A claim older than the reclaim window with no dispatched_at is a relay that died
     * mid-pass; it becomes eligible again rather than being stranded forever.
     *
     * @return Collection<int, Event>
     */
    private function claim(int $limit): Collection
    {
        $staleBefore = now()->subSeconds($this->reclaimAfterSeconds());

        return DB::transaction(function () use ($limit, $staleBefore): Collection {
            $query = Event::query()
                ->whereNull('dispatched_at')
                ->where(fn ($q) => $q->whereNull('claimed_at')->orWhere('claimed_at', '<', $staleBefore))
                ->orderBy('occurred_at')
                ->limit($limit);

            // Postgres/MySQL: let a second relay skip rows this one holds rather than
            // block on them, so concurrent relays share the backlog instead of
            // serialising. SQLite has no row locks and serialises writers anyway, and
            // would reject the clause — hence the driver check rather than a blanket
            // lock. (Expressed as a raw lock: `skipLocked()` is not a builder method.)
            if (in_array(DB::connection()->getDriverName(), ['pgsql', 'mysql', 'mariadb'], true)) {
                $query->lock('for update skip locked');
            }

            $events = $query->get();

            if ($events->isNotEmpty()) {
                Event::query()->whereIn('id', $events->modelKeys())->update(['claimed_at' => now()]);
            }

            return $events;
        });
    }

    private function reclaimAfterSeconds(): int
    {
        $configured = config('cbox-id.events.reclaim_after_seconds', 300);

        // env() yields a STRING for a numeric variable, so is_int() alone silently
        // ignored the knob whenever it was actually configured.
        return is_numeric($configured) && (int) $configured > 0 ? (int) $configured : 300;
    }
}
