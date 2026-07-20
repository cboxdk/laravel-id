<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\PushedAuthorizationRequests;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\PushedAuthorizationRequest;
use Illuminate\Support\Facades\DB;

class PushedAuthorizationService implements PushedAuthorizationRequests
{
    /** Pushed requests are short-lived — they only need to survive the redirect. */
    private const TTL_SECONDS = 90;

    /** RFC 9126 §2.2 request_uri URN prefix. */
    private const URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

    public function push(Client $client, array $params): array
    {
        // The client is fixed by authentication; never let the body override it,
        // and a pushed request may not itself carry a request_uri.
        unset($params['request_uri'], $params['client_secret']);
        $params['client_id'] = $client->client_id;

        $requestUri = self::URN_PREFIX.bin2hex(random_bytes(32));

        PushedAuthorizationRequest::query()->create([
            'request_uri' => $requestUri,
            'client_id' => $client->client_id,
            'params' => $params,
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
        ]);

        return ['request_uri' => $requestUri, 'expires_in' => self::TTL_SECONDS];
    }

    public function consume(string $clientId, string $requestUri): ?array
    {
        return DB::transaction(function () use ($clientId, $requestUri): ?array {
            $record = PushedAuthorizationRequest::query()
                ->where('request_uri', $requestUri)
                ->where('client_id', $clientId)
                ->lockForUpdate()
                ->first();

            if ($record === null || $record->consumed_at !== null || $record->expires_at->isPast()) {
                return null;
            }

            $record->forceFill(['consumed_at' => now()])->save();

            return $record->params;
        });
    }
}
