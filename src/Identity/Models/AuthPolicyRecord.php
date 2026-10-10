<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Enums\SsoEnforcement;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * The stored form of an {@see AuthPolicy} — the environment baseline (null
 * `organization_id`) or an organization's override.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property int $min_length
 * @property bool $require_breach_check
 * @property int|null $max_age_days
 * @property int $reuse_history
 * @property MfaRequirement $mfa
 * @property SsoEnforcement $sso
 * @property int|null $lockout_threshold
 * @property bool $passkeys
 * @property bool $magic_link
 * @property int|null $session_idle_minutes
 * @property int|null $session_absolute_minutes
 * @property bool $bot_challenge
 */
class AuthPolicyRecord extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'auth_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'require_breach_check' => 'boolean',
            'passkeys' => 'boolean',
            'magic_link' => 'boolean',
            'bot_challenge' => 'boolean',
            'mfa' => MfaRequirement::class,
            'sso' => SsoEnforcement::class,
        ];
    }

    /** Rehydrate the typed policy this row stores. */
    public function toPolicy(): AuthPolicy
    {
        return new AuthPolicy(
            minLength: $this->min_length,
            requireBreachCheck: $this->require_breach_check,
            maxAgeDays: $this->max_age_days,
            reuseHistory: $this->reuse_history,
            mfa: $this->mfa,
            sso: $this->sso,
            lockoutThreshold: $this->lockout_threshold,
            passkeys: $this->passkeys,
            magicLink: $this->magic_link,
            sessionIdleMinutes: $this->session_idle_minutes,
            sessionAbsoluteMinutes: $this->session_absolute_minutes,
            botChallenge: $this->bot_challenge,
        );
    }

    /**
     * The column values for a policy — the single place the VO is flattened for
     * storage, so the mapping cannot drift between writes.
     *
     * @return array<string, mixed>
     */
    public static function columnsFor(AuthPolicy $policy): array
    {
        return [
            'min_length' => $policy->minLength,
            'require_breach_check' => $policy->requireBreachCheck,
            'max_age_days' => $policy->maxAgeDays,
            'reuse_history' => $policy->reuseHistory,
            'mfa' => $policy->mfa,
            'sso' => $policy->sso,
            'lockout_threshold' => $policy->lockoutThreshold,
            'passkeys' => $policy->passkeys,
            'magic_link' => $policy->magicLink,
            'session_idle_minutes' => $policy->sessionIdleMinutes,
            'session_absolute_minutes' => $policy->sessionAbsoluteMinutes,
            'bot_challenge' => $policy->botChallenge,
        ];
    }
}
