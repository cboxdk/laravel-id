<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Support\ClientRegistrationDocument;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/register` — OAuth 2.0 Dynamic Client Registration (RFC 7591).
 *
 * Gated by `cbox-id.oauth.dynamic_registration.mode`: `disabled` (403),
 * `protected` (requires the configured initial access token), or `open`.
 */
class RegistrationController
{
    public function __construct(private readonly DynamicClientRegistration $registrar) {}

    public function __invoke(Request $request): JsonResponse
    {
        $gate = $this->gate($request);

        if ($gate !== null) {
            return $gate;
        }

        try {
            $metadata = $this->registrar->validate($this->body($request));
        } catch (InvalidClientMetadata $e) {
            return new JsonResponse(['error' => $e->error, 'error_description' => $e->getMessage()], 400);
        }

        $registration = $this->registrar->register($metadata);

        $document = ClientRegistrationDocument::for($registration->client);
        $document['registration_access_token'] = $registration->registrationAccessToken;
        $document['registration_client_uri'] = url('/oauth/register/'.$registration->client->client_id);

        if ($registration->secret !== null) {
            $document['client_secret'] = $registration->secret;
            $document['client_secret_expires_at'] = 0; // 0 = does not expire
        }

        return new JsonResponse($document, 201);
    }

    /**
     * Enforce the registration mode. Returns an error response to short-circuit,
     * or null to proceed.
     */
    private function gate(Request $request): ?JsonResponse
    {
        $mode = config('cbox-id.oauth.dynamic_registration.mode', 'disabled');

        if ($mode === 'open') {
            return null;
        }

        if ($mode !== 'protected') {
            return new JsonResponse([
                'error' => 'access_denied',
                'error_description' => 'dynamic client registration is disabled',
            ], 403);
        }

        // protected: require the configured initial access token as a bearer.
        $expected = config('cbox-id.oauth.dynamic_registration.initial_access_token');
        $presented = $request->bearerToken();

        if (! is_string($expected) || $expected === '' || ! is_string($presented)
            || ! hash_equals($expected, $presented)) {
            return new JsonResponse([
                'error' => 'invalid_token',
                'error_description' => 'a valid initial access token is required to register',
            ], 401, ['WWW-Authenticate' => 'Bearer']);
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    private function body(Request $request): array
    {
        $data = $request->json()->all();
        $data = $data === [] ? $request->all() : $data;

        $normalized = [];

        foreach ($data as $key => $value) {
            $normalized[(string) $key] = $value;
        }

        return $normalized;
    }
}
