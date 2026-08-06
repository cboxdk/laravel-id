<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Closure;

/**
 * In-memory {@see EnvironmentContext}. Registered as a singleton, so the current
 * environment is stable for the duration of a request or queued job. Suspension
 * is reference-counted to support safe nesting of {@see withoutScope()}.
 */
class EnvironmentContextManager implements EnvironmentContext
{
    private ?Environment $current = null;

    private int $suspensions = 0;

    public function current(): ?Environment
    {
        return $this->current;
    }

    public function requireEnvironment(): Environment
    {
        return $this->current ?? throw new EnvironmentMissing;
    }

    public function has(): bool
    {
        return $this->current !== null;
    }

    public function set(?Environment $environment): void
    {
        $this->current = $environment;
    }

    public function runAs(Environment $environment, Closure $callback): mixed
    {
        $previous = $this->current;
        $this->current = $environment;

        try {
            return $callback();
        } finally {
            $this->current = $previous;
        }
    }

    public function withoutScope(Closure $callback): mixed
    {
        $this->suspensions++;

        try {
            return $callback();
        } finally {
            $this->suspensions--;
        }
    }

    public function isScopingSuspended(): bool
    {
        return $this->suspensions > 0;
    }
}
