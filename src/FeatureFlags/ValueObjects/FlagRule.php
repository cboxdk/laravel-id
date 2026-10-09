<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\ValueObjects;

use Cbox\Id\FeatureFlags\Enums\EvaluationReason;

/**
 * One flag as evaluation needs it: its switches and its rules, nothing else.
 *
 * This is the shape the per-environment cache holds ({@see toArray()} / {@see fromArray()}
 * — plain arrays, so a cached entry survives a deploy that changes this class), and
 * {@see evaluate()} is pure: no database, no clock, no randomness. The same flag asked
 * the same question gives the same answer on every replica, which is what lets a rollout
 * percentage be stable.
 */
final readonly class FlagRule
{
    /**
     * @param  array<string, bool>  $users
     * @param  array<string, bool>  $organizations
     */
    public function __construct(
        public string $key,
        public bool $enabled,
        public bool $defaultValue,
        public ?int $rolloutPercentage,
        public array $users,
        public array $organizations,
    ) {}

    /**
     * Precedence, first match wins: switched off → user rule → organization rule →
     * rollout bucket → default. See {@see EvaluationReason}.
     *
     * The rollout buckets the USER when there is one and the organization otherwise, so a
     * machine token or an organization-only question still lands in a stable bucket. With
     * neither, there is nobody to bucket and the default applies.
     */
    public function evaluate(?string $subjectId, ?string $organizationId): FlagEvaluation
    {
        if (! $this->enabled) {
            return new FlagEvaluation($this->key, false, EvaluationReason::Disabled);
        }

        if ($subjectId !== null && $subjectId !== '' && array_key_exists($subjectId, $this->users)) {
            return new FlagEvaluation($this->key, $this->users[$subjectId], EvaluationReason::UserTarget);
        }

        if ($organizationId !== null && $organizationId !== '' && array_key_exists($organizationId, $this->organizations)) {
            return new FlagEvaluation($this->key, $this->organizations[$organizationId], EvaluationReason::OrganizationTarget);
        }

        $identity = $subjectId !== null && $subjectId !== '' ? $subjectId : $organizationId;

        if ($this->rolloutPercentage !== null && $identity !== null && $identity !== ''
            && self::bucket($this->key, $identity) < $this->rolloutPercentage) {
            return new FlagEvaluation($this->key, true, EvaluationReason::Rollout);
        }

        return new FlagEvaluation($this->key, $this->defaultValue, EvaluationReason::Default);
    }

    /**
     * The subject's stable rollout bucket for this flag, 0–99.
     *
     * The first 32 bits of SHA-256 over `key/identity`, modulo 100. Salting with the flag
     * key means a user in the first 10% of one rollout is not automatically in the first
     * 10% of every other — otherwise the same unlucky people would see every experiment.
     * Raising a percentage only ADDS people: whoever was in at 10% is still in at 20%.
     *
     * Any SDK can reproduce it offline: `int(sha256(key + "/" + id)[0:8], 16) % 100`.
     */
    public static function bucket(string $key, string $identity): int
    {
        return (int) (hexdec(substr(hash('sha256', $key.'/'.$identity), 0, 8)) % 100);
    }

    /**
     * @return array{key: string, enabled: bool, default: bool, rollout: int|null, users: array<string, bool>, organizations: array<string, bool>}
     */
    public function toArray(): array
    {
        return [
            'key' => $this->key,
            'enabled' => $this->enabled,
            'default' => $this->defaultValue,
            'rollout' => $this->rolloutPercentage,
            'users' => $this->users,
            'organizations' => $this->organizations,
        ];
    }

    /**
     * @param  array<mixed>  $row
     */
    public static function fromArray(array $row): self
    {
        $rollout = $row['rollout'] ?? null;

        return new self(
            key: is_string($row['key'] ?? null) ? $row['key'] : '',
            enabled: ($row['enabled'] ?? false) === true,
            defaultValue: ($row['default'] ?? false) === true,
            rolloutPercentage: is_int($rollout) ? $rollout : null,
            users: self::booleans($row['users'] ?? []),
            organizations: self::booleans($row['organizations'] ?? []),
        );
    }

    /**
     * @return array<string, bool>
     */
    private static function booleans(mixed $map): array
    {
        if (! is_array($map)) {
            return [];
        }

        $out = [];

        foreach ($map as $id => $value) {
            $out[(string) $id] = $value === true;
        }

        return $out;
    }
}
