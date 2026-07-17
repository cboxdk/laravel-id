<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;

/**
 * The registry of API-pull directory connectors, keyed by provider. Deny-by-default:
 * a provider with no registered connector is refused, never silently skipped.
 */
final class DirectoryConnectors
{
    /** @var array<string, DirectoryConnector> */
    private array $connectors = [];

    /**
     * @param  iterable<DirectoryConnector>  $connectors
     */
    public function __construct(iterable $connectors = [])
    {
        foreach ($connectors as $connector) {
            $this->connectors[$connector->provider()->value] = $connector;
        }
    }

    public function has(DirectoryProvider $provider): bool
    {
        return isset($this->connectors[$provider->value]);
    }

    public function for(DirectoryProvider $provider): DirectoryConnector
    {
        return $this->connectors[$provider->value]
            ?? throw DirectoryConnectionFailed::make($provider->value, 'No connector is registered for this provider.');
    }
}
