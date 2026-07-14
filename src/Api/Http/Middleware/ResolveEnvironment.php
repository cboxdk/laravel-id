<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Middleware;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Resolves the environment for every request from its host and pins it in the
 * {@see EnvironmentContext} — this is what makes the hard environment scope
 * engage in production. Falls back to a single configured default environment
 * (`cbox-id.environments.default`) for single-tenant / on-prem deployments;
 * otherwise an unknown host is refused rather than served the wrong plane.
 */
final class ResolveEnvironment
{
    public function __construct(
        private readonly EnvironmentResolver $resolver,
        private readonly EnvironmentContext $context,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $environment = $this->resolver->resolveForHost($request->getHost());

        if ($environment === null) {
            // Host matched nothing → fall back to the single-tenant default. An
            // explicit config key (env var / ConfigMap) wins when set; otherwise
            // the environment flagged default in the database, so a host-less,
            // horizontally-scaled deployment needs no per-replica config.
            $default = config('cbox-id.environments.default');
            $environment = is_string($default) && $default !== ''
                ? GenericEnvironment::of($default)
                : $this->resolver->defaultEnvironment();
        }

        abort_if($environment === null, 404, 'Unknown environment for host.');

        $this->context->set($environment);

        return $next($request);
    }
}
