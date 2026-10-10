<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\SignInMethods;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * The default {@see SignInMethods}: the deployment's configuration as the ceiling, the
 * environment's {@see AuthPolicy} beneath it.
 *
 * Stateless, and every answer is read fresh: the policy side is memoised per request by
 * {@see AuthPolicies} already, and the configuration side is configuration. A singleton is
 * therefore safe across requests and queued jobs — there is nothing here to go stale.
 *
 * The policy is resolved from the container on each call rather than injected, because a
 * host may decorate {@see AuthPolicies} with something that itself needs the session
 * manager, which asks this class — a constructor dependency would be a cycle.
 */
class PolicySignInMethods implements SignInMethods
{
    /** The fallback absolute cap when the configuration holds nothing usable: one day. */
    private const DEFAULT_ABSOLUTE_MINUTES = 60 * 24;

    public function passkeysEnabled(): bool
    {
        return $this->deploymentAllowsPasskeys() && $this->policy()->passkeys;
    }

    public function magicLinkEnabled(): bool
    {
        return $this->deploymentAllowsMagicLink() && $this->policy()->magicLink;
    }

    public function sessionAbsoluteMinutes(): int
    {
        $ceiling = $this->deploymentSessionAbsoluteMinutes();
        $chosen = $this->policy()->sessionAbsoluteMinutes;

        return $chosen === null || $chosen < 1 ? $ceiling : min($chosen, $ceiling);
    }

    public function sessionIdleMinutes(): int
    {
        $ceiling = $this->deploymentSessionIdleMinutes();
        $chosen = $this->policy()->sessionIdleMinutes;

        if ($chosen === null || $chosen < 1) {
            return $ceiling;
        }

        // A deployment with no idle timeout puts no ceiling on one — but an idle window
        // longer than the session itself would never fire, so the absolute cap bounds it.
        $bound = $ceiling === 0 ? $this->sessionAbsoluteMinutes() : $ceiling;

        return min($chosen, $bound);
    }

    public function deploymentAllowsPasskeys(): bool
    {
        return self::flag(config('cbox-id.sign_in.passkeys', true));
    }

    public function deploymentAllowsMagicLink(): bool
    {
        return self::flag(config('cbox-id.sign_in.magic_link', true));
    }

    public function deploymentSessionAbsoluteMinutes(): int
    {
        $value = config('cbox-id.sessions.ttl_minutes', self::DEFAULT_ABSOLUTE_MINUTES);
        $minutes = is_numeric($value) ? (int) $value : self::DEFAULT_ABSOLUTE_MINUTES;

        return $minutes < 1 ? self::DEFAULT_ABSOLUTE_MINUTES : $minutes;
    }

    public function deploymentSessionIdleMinutes(): int
    {
        $value = config('cbox-id.sessions.idle_minutes', 0);

        return is_numeric($value) ? max(0, (int) $value) : 0;
    }

    private function policy(): AuthPolicy
    {
        return app(AuthPolicies::class)->forEnvironment();
    }

    /**
     * A configuration switch as a boolean. `env()` already turns `"false"` into false, but a
     * value set from a config cache or a host's own file may still be the string, and a
     * string is truthy — the one way an operator's "off" could silently read as on.
     */
    private static function flag(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? true;
    }
}
