<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Federation\ValueObjects\OAuth2ConnectionConfig;
use Cbox\Id\Federation\ValueObjects\ProviderProfileMap;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Illuminate\Support\Facades\Http;

/**
 * Sign-in against a provider that speaks OAuth 2.0 and nothing more — GitHub, Discord,
 * Facebook. There is no discovery, no `id_token`, and no signature over the claims.
 *
 * What carries the weight instead is narrow and worth being explicit about, because it
 * is easy to mistake this for OIDC and trust it accordingly:
 *
 *  1. The code was exchanged at the provider's own token endpoint, over TLS, using our
 *     client secret — so the access token was issued to US and not to some other app.
 *  2. The profile came back from the endpoint the CATALOGUE names, not one the tenant
 *     chose. An administrator who could type the profile URL could point a connection
 *     labelled "GitHub" at a server that answers whatever they like.
 *
 * That is enough to say "this browser controls that provider account". It is NOT an
 * assertion about the email address attached to it, which is why nothing here marks an
 * address verified and why the resulting principal goes through the same
 * `provisionFederated()` as every other federation path — the one that refuses to merge
 * into an existing account by email.
 */
class OAuth2Client
{
    public function authorizeUrl(ProviderTemplate $template, OAuth2ConnectionConfig $config, string $redirectUri, string $state): string
    {
        $endpoint = $template->authorizationEndpoint
            ?? throw InvalidAssertion::make($template->key.' has no authorization endpoint');

        $query = http_build_query(array_filter([
            'response_type' => 'code',
            'client_id' => $config->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $template->scopes),
            // Opaque, single-use, and checked by the caller on return. Without it the
            // callback is an unauthenticated endpoint that logs somebody in.
            'state' => $state,
        ]));

        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?').$query;
    }

    /**
     * Exchange the code for an access token, then fetch the profile it unlocks.
     */
    public function principal(ProviderTemplate $template, OAuth2ConnectionConfig $config, string $code, string $redirectUri, ?string $connectionId = null): FederatedPrincipal
    {
        $token = $this->accessToken($template, $config, $code, $redirectUri);
        $profile = $this->fetch(
            $template->profileEndpoint ?? throw InvalidAssertion::make($template->key.' has no profile endpoint'),
            $token,
        );

        $subject = $this->stringAt($profile, $template->profile->subject);

        if ($subject === null) {
            throw InvalidAssertion::make($template->key.' profile carried no '.$template->profile->subject);
        }

        return new FederatedPrincipal(
            provider: 'oauth2:'.$template->key,
            subject: $subject,
            email: $this->email($template->profile, $profile, $token),
            name: $this->stringAt($profile, $template->profile->name ?? ''),
            connectionId: $connectionId,
            // Keyed, because the principal's contract says so — a provider that answered
            // a bare list here would otherwise reach the audit trail as one.
            raw: array_filter($profile, 'is_string', ARRAY_FILTER_USE_KEY),
        );
    }

    private function accessToken(ProviderTemplate $template, OAuth2ConnectionConfig $config, string $code, string $redirectUri): string
    {
        $endpoint = $template->tokenEndpoint ?? throw InvalidAssertion::make($template->key.' has no token endpoint');

        $response = Http::asForm()
            ->withOptions($this->pinned($endpoint))
            ->withoutRedirecting()
            // GitHub answers form-encoded unless asked otherwise, and a form-encoded body
            // read as JSON is an empty array — which surfaces as "no access token" rather
            // than as the parsing problem it is.
            ->withHeaders(['Accept' => 'application/json'])
            ->timeout(10)
            ->post($endpoint, [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'client_id' => $config->clientId,
                'client_secret' => $config->clientSecret,
            ]);

        if (! $response->successful()) {
            throw InvalidAssertion::make('token exchange failed');
        }

        $token = $response->json('access_token');

        if (! is_string($token) || $token === '') {
            // Providers here answer 200 with an `error` body rather than a 4xx, so a
            // successful response proves nothing on its own.
            throw InvalidAssertion::make('token response contained no access_token');
        }

        return $token;
    }

    /**
     * The address, including the second call GitHub needs.
     *
     * `/user` returns `email: null` for anyone who has not made theirs public — which is
     * the default — so without this a majority of GitHub sign-ins would arrive with no
     * address at all. The template names the fallback endpoint; nothing here is
     * GitHub-specific beyond that.
     *
     * @param  array<mixed>  $profile
     */
    private function email(ProviderProfileMap $map, array $profile, string $token): ?string
    {
        $email = $this->stringAt($profile, $map->email ?? '');

        if ($email !== null || $map->emailEndpoint === null) {
            return $email;
        }

        $addresses = $this->fetch($map->emailEndpoint, $token);

        // Take the primary. Not the first: the list is not ordered, and picking whichever
        // came back first would attach the account to an address the person may have
        // added and forgotten.
        foreach ($addresses as $entry) {
            if (is_array($entry) && ($entry['primary'] ?? false) === true && is_string($entry['email'] ?? null)) {
                return $entry['email'];
            }
        }

        return null;
    }

    /**
     * GitHub's email endpoint answers a LIST, not an object, so this is deliberately
     * untyped beyond "some array" — the callers know which shape they asked for.
     *
     * @return array<mixed>
     */
    private function fetch(string $endpoint, string $token): array
    {
        $response = Http::withOptions($this->pinned($endpoint))
            ->withoutRedirecting()
            ->withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
                // GitHub refuses requests without one and answers 403, which reads as a
                // permissions problem rather than a missing header.
                'User-Agent' => 'cbox-id',
            ])
            ->timeout(10)
            ->get($endpoint);

        if (! $response->successful()) {
            throw InvalidAssertion::make('profile request failed');
        }

        $body = $response->json();

        return is_array($body) ? $body : throw InvalidAssertion::make('profile response was not an object');
    }

    /**
     * @return array<string, mixed>
     */
    private function pinned(string $endpoint): array
    {
        // These endpoints come from the catalogue rather than from a tenant, so this is
        // belt and braces — but it is the same guard every other outbound call in this
        // package uses, and an entry added later without one would be the exception
        // nobody noticed.
        try {
            return SafeFederationUrl::pinnedOptions($endpoint);
        } catch (UnsafeFederationUrl $e) {
            throw InvalidAssertion::make('endpoint blocked: '.$e->getMessage());
        }
    }

    /**
     * A dot path into the profile, as a string.
     *
     * Numeric ids are cast: GitHub's `id` is a JSON number and Discord's is a string, and
     * a subject that changes type between providers is a subject that fails to match the
     * link written last time.
     *
     * @param  array<mixed>  $profile
     */
    private function stringAt(array $profile, string $path): ?string
    {
        if ($path === '') {
            return null;
        }

        $value = $profile;

        foreach (explode('.', $path) as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return null;
            }

            $value = $value[$segment];
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        return is_string($value) && $value !== '' ? $value : null;
    }
}
