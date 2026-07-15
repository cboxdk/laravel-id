<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Support;

use Cbox\Id\AuditStreaming\Contracts\SiemEventMapper;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Siem\Enums\EventCategory;
use Cbox\Siem\Enums\Outcome;
use Cbox\Siem\Enums\Severity;
use Cbox\Siem\ValueObjects\Party;
use Cbox\Siem\ValueObjects\SiemEvent;
use Illuminate\Support\Str;

/**
 * The default {@see SiemEventMapper}. Conservative and deterministic — it never
 * guesses beyond what the audit entry states.
 *
 * Category (from the action's dotted prefix; default {@see EventCategory::Audit}):
 *  - `auth.*`, `login`, `logout`, `mfa.*`, `password.*` → Authentication
 *  - `session.*`                                        → Session
 *  - `permission.*`, `role.*`, `policy.*`, `access.*`   → Authorization
 *  - `user.*`, `org.*`, `member.*`, `group.*`, `scim.*` → Iam
 *  - `config.*`, `setting.*`, `stream.*`, `webhook.*`   → Configuration
 *  - `threat.*`, `security.*`, `suspicious.*`           → Threat
 *
 * Outcome (default {@see Outcome::Success}): an action whose last segment reads as
 * a negative result — `*.failed`, `*.denied`, `*.rejected`, `*.error`,
 * `*.blocked`, `*.invalid` — maps to {@see Outcome::Failure}. Nothing is ever
 * reported as `Unknown` from an audit entry, because a recorded action happened.
 *
 * Severity (default {@see Severity::Info}): {@see EventCategory::Threat} events are
 * {@see Severity::High}; a {@see Outcome::Failure} is at least {@see Severity::Medium}.
 *
 * The id and the chain-continuity context fields are fixed by contract (see
 * {@see SiemEventMapper}); only the classification above is opinion, and it is the
 * part a host overrides.
 */
class DefaultSiemEventMapper implements SiemEventMapper
{
    public function toSiemEvent(AuditEntry $entry): SiemEvent
    {
        $category = $this->category($entry->action);
        $outcome = $this->outcome($entry->action);

        return new SiemEvent(
            // The chain hash is a stable, unique, content-derived id — the
            // customer SIEM dedups on it and at-least-once redelivery is harmless.
            id: $entry->hash,
            occurredAt: ($entry->recorded_at ?? now())->toDateTimeImmutable(),
            action: $entry->action,
            category: $category,
            outcome: $outcome,
            severity: $this->severity($category, $outcome),
            actor: $entry->actor_id === null
                ? null
                : Party::of($entry->actor_type->value, $entry->actor_id),
            target: $entry->target_type !== null && $entry->target_id !== null
                ? Party::of($entry->target_type, $entry->target_id)
                : null,
            sourceIp: $entry->ip,
            context: $this->context($entry),
        );
    }

    private function category(string $action): EventCategory
    {
        return match (true) {
            $this->startsWithAny($action, ['auth', 'login', 'logout', 'mfa', 'password']) => EventCategory::Authentication,
            $this->startsWithAny($action, ['session']) => EventCategory::Session,
            $this->startsWithAny($action, ['permission', 'role', 'policy', 'access', 'authz']) => EventCategory::Authorization,
            $this->startsWithAny($action, ['user', 'org', 'member', 'group', 'scim', 'directory']) => EventCategory::Iam,
            $this->startsWithAny($action, ['config', 'setting', 'stream', 'webhook', 'client']) => EventCategory::Configuration,
            $this->startsWithAny($action, ['threat', 'security', 'suspicious']) => EventCategory::Threat,
            default => EventCategory::Audit,
        };
    }

    private function outcome(string $action): Outcome
    {
        $tail = Str::afterLast($action, '.');

        return in_array($tail, ['failed', 'failure', 'denied', 'rejected', 'error', 'blocked', 'invalid'], true)
            ? Outcome::Failure
            : Outcome::Success;
    }

    private function severity(EventCategory $category, Outcome $outcome): Severity
    {
        if ($category === EventCategory::Threat) {
            return Severity::High;
        }

        return $outcome === Outcome::Failure ? Severity::Medium : Severity::Info;
    }

    /**
     * The entry's own context, coerced to the SIEM-safe scalar|null shape, PLUS the
     * chain-continuity fields the receiver verifies against. Nested context values
     * (which a SIEM cannot index) are JSON-encoded to a string rather than dropped,
     * so nothing is lost.
     *
     * @return array<string, scalar|null>
     */
    private function context(AuditEntry $entry): array
    {
        $context = [];

        foreach ($entry->context as $key => $value) {
            $context[$key] = is_scalar($value) || $value === null
                ? $value
                : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        // Authoritative chain metadata — added last so it cannot be shadowed by a
        // colliding context key, and so the SIEM can prove continuity/dedup.
        $context['sequence'] = $entry->sequence;
        $context['hash'] = $entry->hash;
        $context['prev_hash'] = $entry->prev_hash;
        $context['organization_id'] = $entry->organization_id;

        return $context;
    }

    /**
     * @param  list<string>  $prefixes
     */
    private function startsWithAny(string $action, array $prefixes): bool
    {
        foreach ($prefixes as $prefix) {
            if ($action === $prefix || Str::startsWith($action, $prefix.'.') || Str::startsWith($action, $prefix.'_')) {
                return true;
            }
        }

        return false;
    }
}
