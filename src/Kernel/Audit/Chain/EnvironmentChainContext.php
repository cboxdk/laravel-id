<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Chain;

use Cbox\AuditChain\Contracts\ChainContext;
use Cbox\AuditChain\ValueObjects\ChainKey;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Closure;

/**
 * Runs a chain sweep inside the chain's own environment: an audit chain's partition IS
 * an environment key (or the `__platform__` sentinel), its signing key belongs to that
 * environment, and its checkpoint row is environment-owned. Signing environment A's
 * chain from environment B's context would either anchor the wrong chain or be refused
 * outright.
 *
 * The platform partition is entered as the environment `__platform__`, exactly as the
 * checkpoint pass always has — so a platform chain's checkpoint is signed with, and
 * verifies against, that environment's key.
 *
 * Resolves the environment context per call, never holds it: this is a singleton and
 * that binding is `scoped`.
 */
class EnvironmentChainContext implements ChainContext
{
    use ResolvesEnvironment;

    public function run(ChainKey $key, Closure $callback): mixed
    {
        return $this->environments()->runAs(GenericEnvironment::of($key->partition), $callback);
    }
}
