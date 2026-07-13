<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;

/**
 * A minimal {@see Environment} backed by a bare key — for when you already hold
 * an environment identifier (resolved from the host/subdomain, an API key, a job
 * payload) and don't need the full Environment model. The Environment model is
 * the production implementation.
 */
final readonly class GenericEnvironment implements Environment
{
    public function __construct(private string $key) {}

    public static function of(string $key): self
    {
        return new self($key);
    }

    public function environmentKey(): string
    {
        return $this->key;
    }
}
