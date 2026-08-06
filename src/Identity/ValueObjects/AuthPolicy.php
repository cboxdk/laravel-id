<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Enums\SsoEnforcement;

/**
 * The authentication rules in force for a tenant: how strong a password must be, how
 * long it may live, whether a second factor or single sign-on is mandatory.
 *
 * An ENVIRONMENT sets the baseline; an ORGANIZATION may override it but only to
 * TIGHTEN — {@see tightenedWith()} is the only way the two combine, so a tenant can
 * never negotiate its way below the operator's floor.
 */
readonly class AuthPolicy
{
    /**
     * @param  int  $minLength  minimum password length
     * @param  bool  $requireBreachCheck  refuse passwords found in a public breach corpus
     * @param  int|null  $maxAgeDays  force a change after this many days; null = never
     * @param  int  $reuseHistory  how many previous passwords may not be reused; 0 = off
     * @param  int|null  $lockoutThreshold  failed attempts before lockout; null = off
     */
    public function __construct(
        public int $minLength = 12,
        public bool $requireBreachCheck = true,
        public ?int $maxAgeDays = null,
        public int $reuseHistory = 0,
        public MfaRequirement $mfa = MfaRequirement::Optional,
        public SsoEnforcement $sso = SsoEnforcement::Off,
        public ?int $lockoutThreshold = null,
    ) {}

    /**
     * Combine an inherited policy with an override, taking the STRICTER value of each
     * field. This is the only supported way to apply an organization's policy on top of
     * its environment's, so an override cannot weaken the baseline — a tenant may demand
     * more of its own people than the operator requires, never less.
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
