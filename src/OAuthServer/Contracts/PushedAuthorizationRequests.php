<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;

interface PushedAuthorizationRequests
{
    /**
     * Store a client's authorization request parameters and return the opaque,
     * single-use request_uri plus its lifetime in seconds (RFC 9126 §2.2).
     *
     * @param  array<array-key, mixed>  $params
     * @return array{request_uri: string, expires_in: int}
     */
    public function push(Client $client, array $params): array;

    /**
     * Consume a request_uri, returning the stored parameters for the given client,
     * or null if it is unknown, expired, already used or belongs to another client.
     * Single-use: a successful consume cannot be repeated.
     *
     * @return array<string, mixed>|null
     */
    public function consume(string $clientId, string $requestUri): ?array;
}
