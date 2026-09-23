<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\Organization\Contracts\CustomerApiKeys;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/api-keys/verify` — an app asks whether a customer API key presented to
 * ITS API is good, and what it may do.
 *
 * The app authenticates exactly as it does at the token endpoint (client_secret_basic,
 * client_secret_post or private_key_jwt); a public client has no credential to prove and
 * is refused. The presented key goes in `key`.
 *
 * Answers `{active, key_id, sub, org, org_role, permissions[], client_id, expires_at}`
 * for a live key bound to the caller, and exactly `{"active": false}` for everything
 * else — unknown, malformed, revoked, expired, another app's key, a holder who left.
 * The endpoint never says which, so it is not an oracle for probing keys; the only
 * distinct answer is the 401 for a caller who failed to authenticate, which is a fact
 * about the caller's own credentials.
 */
class ApiKeyVerificationController
{
    public function __construct(private readonly ClientAuthenticator $clientAuth) {}

    public function __invoke(Request $request, CustomerApiKeys $keys): JsonResponse
    {
        $caller = $this->clientAuth->authenticateConfidential($request);

        if ($caller === null) {
            return response()->json(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Basic realm="api-keys"']);
        }

        return response()->json($keys->verify($caller, $request->string('key')->toString())->toArray());
    }
}
