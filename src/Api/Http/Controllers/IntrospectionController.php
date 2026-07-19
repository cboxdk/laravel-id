<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/introspect` — RFC 7662 token introspection. The endpoint is
 * protected: the caller must authenticate as a registered client (RFC 7662 §2.1),
 * otherwise it becomes an open oracle for probing token validity.
 */
final class IntrospectionController
{
    public function __construct(private readonly ClientAuthenticator $clientAuth) {}

    public function __invoke(Request $request, TokenIntrospector $introspector): JsonResponse
    {
        $caller = $this->clientAuth->authenticateConfidential($request);

        if ($caller === null) {
            return response()->json(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Basic realm="introspection"']);
        }

        $callerId = $caller->client_id;

        $result = $introspector->introspect($request->string('token')->toString());

        // Ownership (RFC 7662 §2.1): a client may only introspect its own tokens.
        // Anything else answers `active: false` so the endpoint isn't an oracle
        // for probing other clients' tokens.
        if (! $result->active || $result->clientId !== $callerId) {
            return response()->json(['active' => false]);
        }

        return response()->json($this->body($result));
    }

    /**
     * The full RFC 7662 §2.2 introspection response, surfacing the token's
     * lifetime and audience (`exp`/`iat`/`nbf`/`aud`/`iss`/`jti`) and its type —
     * `DPoP` for a sender-constrained token (RFC 9449), else `Bearer`. Fields absent
     * from the token are omitted rather than sent null.
     *
     * @return array<string, mixed>
     */
    private function body(Introspection $result): array
    {
        $claims = $result->claims;

        $body = [
            'active' => true,
            'sub' => $result->subject,
            'client_id' => $result->clientId,
            'scope' => implode(' ', $result->scopes),
            'token_type' => $result->confirmationThumbprint() !== null ? 'DPoP' : 'Bearer',
        ];

        foreach (['exp', 'iat', 'nbf'] as $timestamp) {
            if (is_numeric($claims[$timestamp] ?? null)) {
                $body[$timestamp] = (int) $claims[$timestamp];
            }
        }

        foreach (['iss', 'jti'] as $string) {
            if (is_string($claims[$string] ?? null) && $claims[$string] !== '') {
                $body[$string] = $claims[$string];
            }
        }

        // `aud` is a string or an array of audiences (JWT / RFC 7662).
        $aud = $claims['aud'] ?? null;
        if (is_string($aud) || (is_array($aud) && $aud !== [])) {
            $body['aud'] = $aud;
        }

        return $body;
    }
}
