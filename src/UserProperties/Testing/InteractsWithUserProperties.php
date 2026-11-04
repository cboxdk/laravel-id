<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Testing;

use Cbox\Id\UserProperties\Contracts\PropertyNamespaces;
use Cbox\Id\UserProperties\Models\PropertyNamespace;

trait InteractsWithUserProperties
{
    /**
     * @param  list<string>  $readers
     * @param  list<string>  $writers
     * @param  array<string, string>  $webhooks
     */
    protected function makePropertyNamespace(string $name, array $readers, array $writers = [], array $webhooks = []): PropertyNamespace
    {
        return app(PropertyNamespaces::class)->configure($name, $readers, $writers, $webhooks);
    }
}
