<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\SignInMethods;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Enums\SsoEnforcement;

/**
 * The authentication rules in force for a tenant: how strong a password must be, how
 * long it may live, whether a second factor or single sign-on is mandatory.
 *
 * An ENVIRONMENT sets the baseline; an ORGANIZATION may override it but only to
 * TIGHTEN — {@see tightenedWith()} is the only way the two combine, so a tenant can
 * never negotiate its way below the operator's floor.
 *
 * ENVIRONMENT-WIDE SETTINGS RIDE ALONG, and are never an organization's to change: whether
 * passkeys and magic links are offered, how long a session lasts, and whether the host may
 * put a bot challenge in front of a suspicious attempt. Each of them is decided at a point
 * where the organization is usually not known yet — the sign-in page before an address is
 * typed, a session cookie read on every request — so a per-organization answer could not be
 * enforced honestly. {@see tightenedWith()} therefore keeps the BASELINE's value for them,
 * whatever an override row happens to hold (see {@see isEnvironmentWide()}).
 *
 * Each of them is also bounded by the DEPLOYMENT: an environment may switch a method off
 * that the deployment offers, or shorten a session below the deployment's maximum, never
 * the reverse. That ceiling is applied where the setting is read
 * ({@see SignInMethods}), not here, because it is
 * configuration rather than policy and changes without a write.
 */
readonly class AuthPolicy
{
    /**
     * @param  int  $minLength  minimum password length
     * @param  bool  $requireBreachCheck  refuse passwords found in a public breach corpus
     * @param  int|null  $maxAgeDays  force a change after this many days; null = never
     * @param  int  $reuseHistory  how many previous passwords may not be reused; 0 = off
     * @param  int|null  $lockoutThreshold  failed attempts before lockout; null = off
     * @param  bool  $passkeys  environment-wide: passkeys may be used to sign in and be added
     * @param  bool  $magicLink  environment-wide: a one-time sign-in link may be emailed and redeemed
     * @param  int|null  $sessionIdleMinutes  environment-wide: a session ends after this much
     *                                        inactivity; null = the deployment's own idle timeout
     * @param  int|null  $sessionAbsoluteMinutes  environment-wide: a session ends this long after it
     *                                            started, however active; null = the deployment's own cap
     * @param  bool  $botChallenge  environment-wide: the host may challenge an attempt its risk
     *                              scoring flagged with a human check, where the deployment has one
     */
    public function __construct(
        public int $minLength = 12,
        public bool $requireBreachCheck = true,
        public ?int $maxAgeDays = null,
        public int $reuseHistory = 0,
        public MfaRequirement $mfa = MfaRequirement::Optional,
        public SsoEnforcement $sso = SsoEnforcement::Off,
        public ?int $lockoutThreshold = null,
        public bool $passkeys = true,
        public bool $magicLink = true,
        public ?int $sessionIdleMinutes = null,
        public ?int $sessionAbsoluteMinutes = null,
        public bool $botChallenge = true,
    ) {}

    /**
     * The fields an organization's override never changes — named, so a caller that renders
     * or validates an override can leave them out by asking rather than by keeping a second
     * list that drifts.
     *
     * @return list<string> constructor parameter names
     */
    public static function environmentWide(): array
    {
        return ['passkeys', 'magicLink', 'sessionIdleMinutes', 'sessionAbsoluteMinutes', 'botChallenge'];
    }

    /** Whether a field is one of {@see environmentWide()}. */
    public static function isEnvironmentWide(string $field): bool
    {
        return in_array($field, self::environmentWide(), true);
    }

    /**
     * Combine an inherited policy with an override, taking the STRICTER value of each
     * field. This is the only supported way to apply an organization's policy on top of
     * its environment's, so an override cannot weaken the baseline — a tenant may demand
     * more of its own people than the operator requires, never less.
     *
     * The environment-wide settings ({@see environmentWide()}) are taken from `$this` — the
     * baseline — and the override's values for them are ignored. An override row stores
     * them only because it is the same shape; an organization does not decide them.
     */
    public function tightenedWith(self $override): self
    {
        return new self(
            minLength: max($this->minLength, $override->minLength),
            requireBreachCheck: $this->requireBreachCheck || $override->requireBreachCheck,
            maxAgeDays: self::shorter($this->maxAgeDays, $override->maxAgeDays),
            reuseHistory: max($this->reuseHistory, $override->reuseHistory),
            mfa: $this->mfa->atLeast($override->mfa),
            sso: $this->sso->atLeast($override->sso),
            lockoutThreshold: self::shorter($this->lockoutThreshold, $override->lockoutThreshold),
            passkeys: $this->passkeys,
            magicLink: $this->magicLink,
            sessionIdleMinutes: $this->sessionIdleMinutes,
            sessionAbsoluteMinutes: $this->sessionAbsoluteMinutes,
            botChallenge: $this->botChallenge,
        );
    }

    /**
     * The stricter of two optional limits. Null means "no limit", so ANY concrete limit
     * is stricter than null, and between two limits the smaller one wins.
     */
    private static function shorter(?int $a, ?int $b): ?int
    {
        if ($a === null) {
            return $b;
        }

        if ($b === null) {
            return $a;
        }

        return min($a, $b);
    }
}
