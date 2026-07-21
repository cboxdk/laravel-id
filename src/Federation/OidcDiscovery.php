<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Exceptions\OidcDiscoveryFailed;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Federation\ValueObjects\DiscoveredOidcProvider;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Resolves an OpenID Provider's endpoints from its issuer via the discovery document
 * (`{issuer}/.well-known/openid-configuration`, OpenID Connect Discovery 1.0), so an
 * admin enters only the issuer and the authorization/token endpoints — which
 * {@see OidcClient} needs — are filled in rather than hand-copied.
 *
 * The fetch goes through the same DNS-pinned SSRF gate ({@see SafeFederationUrl}) as
 * every other admin-configured federation URL, so a discovery URL cannot be aimed at
 * the cloud metadata endpoint or an internal host. The document's advertised `issuer`
 * must match the requested one (OIDC Discovery §4.3) — a mismatch is rejected so a
 * hostile document cannot redirect the flow to attacker-controlled endpoints while
 * claiming a trusted issuer.
 */
class OidcDiscovery
{
    /**
     * @throws OidcDiscoveryFailed
     * @throws UnsafeFederationUrl when the URL resolves to a non-public destination
     */
    public function fromIssuer(string $issuer): DiscoveredOidcProvider
    {
        $issuer = rtrim(trim($issuer), '/');

        if ($issuer === '') {
            throw OidcDiscoveryFailed::make('the issuer was empty.');
        }

        $url = $issuer.'/.well-known/openid-configuration';
        $pinned = SafeFederationUrl::pinnedOptions($url);

        try {
            $response = Http::withOptions($pinned)->timeout(10)->get($url);
        } catch (Throwable $e) {
            throw OidcDiscoveryFailed::make('could not fetch the discovery document: '.$e->getMessage());
        }

        if (! $response->successful()) {
            throw OidcDiscoveryFailed::make("the discovery URL returned HTTP {$response->status()}.");
        }

        $document = $response->json();

        if (! is_array($document)) {
            throw OidcDiscoveryFailed::make('the discovery document was not a JSON object.');
        }

        $documentIssuer = rtrim($this->string($document, 'issuer'), '/');
        if ($documentIssuer !== '' && $documentIssuer !== $issuer) {
            throw OidcDiscoveryFailed::make('the discovery document issuer does not match the configured issuer.');
        }

        $provider = new DiscoveredOidcProvider(
            issuer: $issuer,
            authorizationEndpoint: $this->string($document, 'authorization_endpoint'),
            tokenEndpoint: $this->string($document, 'token_endpoint'),
            jwksUri: $this->optionalString($document, 'jwks_uri'),
            userinfoEndpoint: $this->optionalString($document, 'userinfo_endpoint'),
        );

        if (! $provider->isComplete()) {
            throw OidcDiscoveryFailed::make('the discovery document is missing the authorization or token endpoint.');
        }

        return $provider;
    }

    /**
     * @param  array<array-key, mixed>  $document
     */
    private function string(array $document, string $key): string
    {
        $value = $document[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    /**
     * @param  array<array-key, mixed>  $document
     */
    private function optionalString(array $document, string $key): ?string
    {
        $value = $this->string($document, $key);

        return $value !== '' ? $value : null;
    }
}
