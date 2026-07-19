<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\OAuthServer\ClientAssertion\ClientAssertionValidator;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Http\Request;

/**
 * The single place OAuth client credentials are read and verified, so every
 * credential-bearing endpoint (`/oauth/token`, `/introspect`, `/revoke`, `/par`)
 * authenticates a client the same way.
 *
 * Three methods, in precedence order: `private_key_jwt` (RFC 7523 — a signed
 * `client_assertion` verified against the client's registered keys), then HTTP Basic
 * (RFC 6749 §2.3.1, `client_secret_basic`), then the `client_id`/`client_secret` body
 * (`client_secret_post`). The RFC forbids combining mechanisms, so a request mixing an
 * assertion with a secret — or Basic with body credentials — is refused. Secrets are
 * verified in constant time by the {@see ClientRegistry}; public clients (no secret,
 * `none`) authenticate by `client_id` alone where the endpoint allows it.
 */
final class ClientAuthenticator
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly ClientAssertionValidator $assertions,
    ) {}

    /**
     * Authenticate a client that MAY be public (`none`): a confidential client
     * (one that holds a secret) must present a valid secret, while a public client
     * authenticates by `client_id` alone. Returns null when the client is unknown,
     * a confidential secret is wrong, or both credential mechanisms were combined.
     */
    public function authenticate(Request $request): ?Client
    {
        if ($this->hasAssertion($request)) {
            return $this->assertionClient($request);
        }

        $credentials = $this->credentials($request);

        if ($credentials === null) {
            return null;
        }

        [$clientId, $secret] = $credentials;
        $client = $this->clients->byClientId($clientId);

        if ($client === null) {
            return null;
        }

        // Confidential clients (those holding a secret) must verify it; public
        // clients (no stored secret) need none.
        if ($client->secret_hash !== null && ! $this->clients->verifySecret($client, $secret)) {
            return null;
        }

        return $client;
    }

    /**
     * Authenticate a confidential client: a valid secret is REQUIRED. Used by the
     * `client_credentials` grant and the introspection/revocation endpoints, which
     * have no public-client mode. Public clients are refused.
     */
    public function authenticateConfidential(Request $request): ?Client
    {
        if ($this->hasAssertion($request)) {
            return $this->assertionClient($request);
        }

        $credentials = $this->credentials($request);

        if ($credentials === null) {
            return null;
        }

        [$clientId, $secret] = $credentials;
        $client = $this->clients->byClientId($clientId);

        return $client !== null && $this->clients->verifySecret($client, $secret) ? $client : null;
    }

    private function hasAssertion(Request $request): bool
    {
        return $request->string('client_assertion')->toString() !== '';
    }

    /**
     * Authenticate via `private_key_jwt` (RFC 7523). Refuses a wrong assertion type,
     * and — per RFC 6749 §2.3 — an assertion COMBINED with a secret or Basic header.
     */
    private function assertionClient(Request $request): ?Client
    {
        if ($request->string('client_assertion_type')->toString() !== ClientAssertionValidator::ASSERTION_TYPE) {
            return null;
        }

        $basicUser = $request->getUser();
        $combined = (is_string($basicUser) && $basicUser !== '') || $request->string('client_secret')->toString() !== '';

        if ($combined) {
            return null;
        }

        return $this->assertions->verify($request->string('client_assertion')->toString());
    }

    /**
     * Extract (client_id, client_secret), preferring HTTP Basic over the body.
     * Returns null when no `client_id` is present, or when both mechanisms are
     * combined (RFC 6749 §2.3.1: "a client MUST NOT use more than one
     * authentication method in each request").
     *
     * @return array{string, string}|null
     */
    private function credentials(Request $request): ?array
    {
        $basicUser = $request->getUser();
        $hasBasic = is_string($basicUser) && $basicUser !== '';

        $bodyId = $request->string('client_id')->toString();
        $bodySecret = $request->string('client_secret')->toString();
        $hasBody = $bodyId !== '' || $bodySecret !== '';

        if ($hasBasic && $hasBody) {
            return null;
        }

        if ($hasBasic) {
            return [$basicUser, (string) $request->getPassword()];
        }

        return $bodyId === '' ? null : [$bodyId, $bodySecret];
    }
}
