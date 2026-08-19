<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\ClientRegistrationDocument;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * `GET|PUT|DELETE /oauth/register/{client}` — RFC 7592 client configuration
 * endpoint. Every operation is authenticated by the registration access token
 * issued at registration; the token scopes access to exactly one client.
 */
class RegisteredClientController
{
    public function __construct(private readonly DynamicClientRegistration $registrar) {}

    public function show(Request $request, string $client): JsonResponse
    {
        $authenticated = $this->authenticate($request, $client);

        return $authenticated instanceof Client
            ? new JsonResponse(ClientRegistrationDocument::for($authenticated))
            : $this->unauthorized();
    }

    public function update(Request $request, string $client): JsonResponse
    {
        $authenticated = $this->authenticate($request, $client);

        if (! $authenticated instanceof Client) {
            return $this->unauthorized();
        }

        try {
            $metadata = $this->registrar->validate($request->json()->all());
        } catch (InvalidClientMetadata $e) {
            return new JsonResponse(['error' => $e->error, 'error_description' => $e->getMessage()], 400);
        }

        $updated = $this->registrar->update($authenticated, $metadata);

        $document = ClientRegistrationDocument::for($updated->client);

        // RFC 7592 §2.2: the response states the client's current registration. When the
        // update moved it into a shared-secret method it had no secret for, the new one is
        // that registration — and this is the only time it is ever readable.
        if ($updated->secret !== null) {
            $document['client_secret'] = $updated->secret;
        }

        return new JsonResponse($document);
    }

    public function destroy(Request $request, string $client): Response|JsonResponse
    {
        $authenticated = $this->authenticate($request, $client);

        if (! $authenticated instanceof Client) {
            return $this->unauthorized();
        }

        $this->registrar->delete($authenticated);

        return response()->noContent();
    }

    private function authenticate(Request $request, string $clientId): ?Client
    {
        $token = $request->bearerToken();

        return is_string($token) && $token !== ''
            ? $this->registrar->authenticate($clientId, $token)
            : null;
    }

    private function unauthorized(): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'invalid_token', 'error_description' => 'invalid registration access token'],
            401,
            ['WWW-Authenticate' => 'Bearer'],
        );
    }
}
