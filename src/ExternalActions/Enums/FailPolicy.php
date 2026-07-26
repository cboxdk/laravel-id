<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Enums;

/**
 * What happens when a hook cannot be CONSULTED — the endpoint timed out, refused the
 * connection, answered 500, or replied with something unparseable. This is a distinct
 * question from what happens when a hook is consulted and says deny: a deny always
 * denies, at every hook point, and no configuration turns that off.
 *
 *  - FailClosed — an unreachable hook denies the operation. Correct for a GATE: a
 *    security control that fails open is not a control. The cost is that the hook's
 *    availability becomes the operation's availability.
 *  - FailOpen — an unreachable hook is skipped and the operation proceeds. Correct
 *    where the blast radius of the hook being down is worse than the risk of one
 *    operation going unexamined — most obviously on the login path, where fail-closed
 *    means a customer's hook outage locks every one of their users out.
 *
 * Every hook point ships a default it can justify ({@see HookPoint::failPolicy()});
 * the tradeoff is genuinely the host's to make, so both a per-hook and a global
 * override exist. Precedence, most specific first:
 *
 *   1. `cbox-id.external_actions.fail_policy.<hook>` — 'open' | 'closed' (or a bool)
 *   2. `cbox-id.external_actions.fail_open` — a bool, applied to EVERY hook point
 *   3. the hook point's own default
 *
 * Leaving `fail_open` unset (null) is what lets the per-hook defaults apply; setting
 * it to `false` is an explicit "close everything", which is honoured.
 */
enum FailPolicy: string
{
    case FailClosed = 'closed';

    case FailOpen = 'open';

    /**
     * The effective policy for a hook point, resolved through the precedence above.
     */
    public static function for(HookPoint $hookPoint): self
    {
        $perHook = self::read(config('cbox-id.external_actions.fail_policy.'.$hookPoint->value));

        if ($perHook !== null) {
            return $perHook;
        }

        return self::read(config('cbox-id.external_actions.fail_open')) ?? $hookPoint->failPolicy();
    }

    public function isOpen(): bool
    {
        return $this === self::FailOpen;
    }

    /**
     * Read a configured value as a policy, tolerating the shapes config actually
     * arrives in: the enum's own strings, a bool, or the string a `.env` file yields
     * before Laravel casts it. Anything else is "not configured", so a typo falls
     * back to the hook's default rather than silently opening a gate.
     */
    private static function read(mixed $value): ?self
    {
        if ($value instanceof self) {
            return $value;
        }

        if (is_bool($value)) {
            return $value ? self::FailOpen : self::FailClosed;
        }

        if (! is_string($value) || $value === '') {
            return null;
        }

        return match (strtolower($value)) {
            'open', 'fail_open', 'true', '1' => self::FailOpen,
            'closed', 'fail_closed', 'false', '0' => self::FailClosed,
            default => null,
        };
    }
}
