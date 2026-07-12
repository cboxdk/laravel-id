<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Testing;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;

trait InteractsWithFederation
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function makeConnection(
        string $organizationId,
        ConnectionType $type = ConnectionType::Saml,
        string $name = 'Okta',
        array $config = [],
        bool $active = true,
    ): Connection {
        $connections = app(Connections::class);
        $connection = $connections->create($organizationId, $type, $name, $config);

        if ($active) {
            $connections->activate($connection->id);
        }

        return $connection->refresh();
    }
}
