<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Enums;

/**
 * What an external action's response says to do — the only three answers there are.
 *
 * IT WAS A STRING COMPARISON, and the comparison was `($json['action'] ?? 'continue')
 * === 'deny'`. Everything that was not exactly `deny` continued: an absent `action`, a
 * misspelling, and — the case that actually bites — `DENY`. A customer whose handler
 * answered `{"action":"DENY","reason":"blocked domain"}` had their gate ignored on every
 * request, with a 2xx response so nothing was recorded as a failure. Their dashboard
 * showed the hook firing successfully while it blocked nothing.
 *
 * That contradicted the hook points' own contract. {@see HookPoint::failPolicy()} marks
 * `TokenMinting`, `PreRegistration` and `PrePasswordChange` `FailClosed`, with the comment
 * "an unanswered gate must not read as permission" — and an unrecognised answer is an
 * unanswered gate.
 *
 * So parsing lives here and returns null on anything it does not recognise, which routes
 * the response to the hook point's fail policy instead of to `continue`. Case-insensitive
 * because a JSON verb is prose from another team's codebase, not a protocol token, and
 * rejecting `DENY` on casing alone would be pedantry that fails OPEN.
 */
enum ActionVerdict: string
{
    /** Proceed, optionally merging the response's `claims` as enrichment. */
    case Continue = 'continue';

    /** Refuse the operation the hook guards, with the response's `reason`. */
    case Deny = 'deny';

    /**
     * Parse an action verb, or null when it is absent or unrecognised.
     *
     * Null is NOT "continue". The caller must send it to the hook point's fail policy —
     * that distinction is the whole point of this method existing.
     */
    public static function parse(mixed $value): ?self
    {
        if (! is_string($value)) {
            return null;
        }

        foreach (self::cases() as $case) {
            if (strcasecmp($case->value, $value) === 0) {
                return $case;
            }
        }

        return null;
    }
}
