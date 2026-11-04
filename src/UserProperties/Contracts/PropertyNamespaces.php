<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Contracts;

use Cbox\Id\UserProperties\Models\PropertyNamespace;

/** Control-plane capability. Never expose to an ordinary application token. */
interface PropertyNamespaces
{
    /**
     * Writers also need explicit read access. Webhooks map endpoint ids to reader client ids.
     *
     * @param  list<string>  $readers
     * @param  list<string>  $writers
     * @param  array<string, string>  $webhooks
     */
    public function configure(string $name, array $readers, array $writers, array $webhooks = []): PropertyNamespace;
}
