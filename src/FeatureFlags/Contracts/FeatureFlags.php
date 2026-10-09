<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Contracts;

use Cbox\Id\FeatureFlags\Exceptions\InvalidFeatureFlag;
use Cbox\Id\FeatureFlags\Exceptions\UnknownFeatureFlag;
use Cbox\Id\FeatureFlags\Models\FeatureFlag;
use Cbox\Id\FeatureFlags\ValueObjects\FeatureFlagChanges;
use Cbox\Id\FeatureFlags\ValueObjects\FlagEvaluation;
use Cbox\Id\FeatureFlags\ValueObjects\NewFeatureFlag;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;

/**
 * Feature flags: named switches an app asks about per user and organization, defined per
 * environment and delivered in the token (`feature_flags` scope), over UserInfo, and by
 * asking here.
 *
 * A flag has a key, a default (on or off), a kill switch (`enabled`), and targeting:
 * rules that turn it on or off for named users and named organizations, and a rollout
 * percentage over everyone else. Evaluation precedence, first match wins:
 *
 *     switched off → user rule → organization rule → rollout bucket → default
 *
 * Evaluation reads one cached, compiled copy of the environment's flags — no query per
 * question — and every change invalidates it. Writes are audited (`feature_flag.created`,
 * `.updated`, `.deleted`, with the actor the caller names) and emitted as the webhook
 * events of the same names.
 *
 * Everything is environment-owned: a flag, and every user or organization its rules name,
 * belongs to the current environment, and another environment's flags are invisible.
 */
interface FeatureFlags
{
    /**
     * Every flag in the environment, ordered by key, with its targets loaded.
     *
     * @return list<FeatureFlag>
     */
    public function all(): array;

    public function find(string $flagId): ?FeatureFlag;

    public function findByKey(string $key): ?FeatureFlag;

    /**
     * @throws InvalidFeatureFlag when the key is malformed or taken, or the targeting names
     *                            a user or organization this environment does not have
     */
    public function create(NewFeatureFlag $flag, ?AuditActor $actor = null): FeatureFlag;

    /**
     * Change what `$changes` names, and nothing else. A change that changes nothing is
     * neither audited nor announced.
     *
     * @throws UnknownFeatureFlag
     * @throws InvalidFeatureFlag
     */
    public function update(string $flagId, FeatureFlagChanges $changes, ?AuditActor $actor = null): FeatureFlag;

    /**
     * Delete a flag and its rules. Code still asking for its key gets `false`.
     *
     * @throws UnknownFeatureFlag
     */
    public function delete(string $flagId, ?AuditActor $actor = null): void;

    /**
     * Whether the flag is on for this subject, asked in this organization. An unknown key
     * is off.
     */
    public function isEnabled(string $key, ?string $subjectId, ?string $organizationId = null): bool;

    /**
     * As {@see isEnabled()}, with the rule that decided.
     */
    public function evaluate(string $key, ?string $subjectId, ?string $organizationId = null): FlagEvaluation;

    /**
     * The keys of every flag that is on for this subject in this organization, sorted —
     * exactly what the `feature_flags` claim carries.
     *
     * @return list<string>
     */
    public function forSubject(?string $subjectId, ?string $organizationId = null): array;

    /**
     * Every flag's answer for this subject in this organization, keyed by flag key.
     *
     * @return array<string, FlagEvaluation>
     */
    public function evaluateAll(?string $subjectId, ?string $organizationId = null): array;
}
