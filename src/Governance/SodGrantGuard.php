<?php

declare(strict_types=1);

namespace Cbox\Id\Governance;

use Cbox\Id\AccessControl\Contracts\DescribesGrantRefusal;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Cbox\Id\Governance\Models\SodPolicy;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/**
 * Segregation of duties as a veto on every role grant, whatever produced it.
 *
 * The rule already existed and was already correct — it was only ever asked on the paths
 * a host could get in front of. Directory-driven grants happen INSIDE the framework, so
 * a group→role mapping created the toxic pairs the console refuses, quietly, on every
 * reconcile. That is the shape of gap that loses a security review: you demonstrate the
 * refusal, and then someone asks what happens when the two roles arrive from the
 * customer's own identity provider.
 *
 * Reads the policy's NAME for the refusal message rather than echoing an id, because
 * every consumer of the message either shows it to a person or writes it into an audit
 * entry a person reads later, and "Approver ⊗ Payer" answers the question that
 * "sod:01J2X…" only raises.
 */
class SodGrantGuard implements DescribesGrantRefusal
{
    private ?SourceMessage $lastRefusal = null;

    /**
     * Resolved lazily, not injected.
     *
     * `DatabaseSegregationOfDuties` depends on `Roles`, and `RoleService` now depends on
     * this guard — so constructor injection closes a container cycle and every role
     * operation dies with a CircularDependencyException. Reaching for the container at
     * call time breaks it, the same way `ResolvesEnvironment` does elsewhere in this
     * package for the same class of reason.
     */
    private function sod(): SegregationOfDuties
    {
        return app(SegregationOfDuties::class);
    }

    public function refuse(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): ?string {
        $this->lastRefusal = $this->describe($organizationId, $userId, $roleId);

        return $this->lastRefusal?->english();
    }

    public function lastRefusalMessage(): ?SourceMessage
    {
        return $this->lastRefusal;
    }

    private function describe(string $organizationId, string $userId, string $roleId): ?SourceMessage
    {
        $decision = $this->sod()->evaluate($organizationId, $userId, $roleId);

        if ($decision->allowed) {
            return null;
        }

        $name = $this->named($decision->reason);

        return $name === null
            ? new SourceMessage('This role conflicts with one the user already holds.')
            : new SourceMessage('This role conflicts with one the user already holds under the rule ":name".', ['name' => $name]);
    }

    /**
     * The offending policy's name, when the decision names one. `evaluate()` returns
     * `sod:<policy id>`; anything else (or a policy since deleted) degrades to no name
     * rather than to a broken sentence.
     */
    private function named(string $reason): ?string
    {
        if (! str_starts_with($reason, 'sod:')) {
            return null;
        }

        $name = SodPolicy::query()->whereKey(substr($reason, 4))->value('name');

        return is_string($name) && $name !== '' ? $name : null;
    }
}
