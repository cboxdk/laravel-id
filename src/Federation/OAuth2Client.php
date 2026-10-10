<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
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
            // The catalogue's scopes first — sign-in reads what they unlock — then whatever
            // the administrator added, never in place of them.
            'scope' => implode(' ', array_values(array_unique([...$template->scopes, ...$config->scopes]))),
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

        [$email, $listedVerified] = $this->email($template->profile, $profile, $token);

        return new FederatedPrincipal(
            provider: 'oauth2:'.$template->key,
            subject: $subject,
            email: $email,
            name: $this->stringAt($profile, $template->profile->name ?? ''),
            connectionId: $connectionId,

            // The catalogue names WHERE each provider puts this, because plain OAuth 2.0
            // standardises nothing — Discord uses `verified` on the user object,
            // Bitbucket `is_confirmed` on each entry of its address list. Read at last,
            // after being declared on nine entries and consumed by none.
            emailVerified: $listedVerified ?? $this->verifiedFlag($profile, $template->profile->emailVerified),
            // Keyed, because the principal's contract says so — a provider that answered
            // a bare list here would otherwise reach the audit trail as one.
            raw: array_filter($profile, 'is_string', ARRAY_FILTER_USE_KEY),
        );
    }

    private function accessToken(ProviderTemplate $template, OAuth2ConnectionConfig $config, string $code, string $redirectUri): string
    {
        $endpoint = $template->tokenEndpoint ?? throw InvalidAssertion::make($template->key.' has no token endpoint');

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ];
        $headers = [
            // GitHub answers form-encoded unless asked otherwise, and a form-encoded body
            // read as JSON is an empty array — which surfaces as "no access token" rather
            // than as the parsing problem it is.
            'Accept' => 'application/json',
        ];

        // ONE of the two, never both. RFC 6749 §2.3 forbids a client from using more
        // than one authentication method per request, and a server that enforces it
        // answers `invalid_request` — which reads as a bad code, not a bad request.
        if ($template->tokenEndpointAuthMethod === TokenEndpointAuthMethod::ClientSecretBasic) {
            $headers['Authorization'] = TokenEndpointAuthMethod::basicCredentials($config->clientId, $config->clientSecret);
        } else {
            $form['client_id'] = $config->clientId;
            $form['client_secret'] = $config->clientSecret;
        }

        $response = Http::asForm()
            ->withOptions($this->pinned($endpoint))
            ->withoutRedirecting()
            ->withHeaders($headers)
            ->timeout(10)
            ->post($endpoint, $form);

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
     * The address, including the second call GitHub and Bitbucket need, and whether the
     * address list vouched for it.
     *
     * `/user` returns `email: null` for anyone who has not made theirs public on GitHub —
     * which is the default — and Bitbucket's `/user` carries no address at all, so without
     * this most sign-ins from either would arrive with no address. The template names the
     * fallback endpoint and the shape of its answer; nothing here is provider-specific.
     *
     * The second element is true only when the map judges entries by a verified flag and
     * the chosen entry carried an explicit true; null otherwise — never false, because an
     * absent claim is not a denial we should invent.
     *
     * @param  array<mixed>  $profile
     * @return array{0: ?string, 1: ?bool}
     */
    private function email(ProviderProfileMap $map, array $profile, string $token): array
    {
        $email = $this->stringAt($profile, $map->email ?? '');

        if ($email !== null || $map->emailEndpoint === null) {
            return [$email, null];
        }

        $response = $this->fetch($map->emailEndpoint, $token);
        $addresses = $map->emailListPath === null ? $response : data_get($response, $map->emailListPath);

        if (! is_array($addresses)) {
            return [null, null];
        }

        // Take the primary. Not the first: the list is not ordered, and picking whichever
        // came back first would attach the account to an address the person may have
        // added and forgotten.
        foreach ($addresses as $entry) {
            if (! is_array($entry) || ($entry[$map->emailEntryPrimary] ?? false) !== true) {
                continue;
            }

            $address = $entry[$map->emailEntryAddress] ?? null;

            if (! is_string($address) || $address === '') {
                continue;
            }

            if ($map->emailEntryVerified === null) {
                return [$address, null];
            }

            // A primary the provider has not confirmed is not taken at all — see
            // ProviderProfileMap::$emailEntryVerified for why "take it, unverified" is
            // not the safe middle ground it looks like.
            return ($entry[$map->emailEntryVerified] ?? null) === true ? [$address, true] : [null, null];
        }

        return [null, null];
    }

    /**
     * GitHub's email endpoint answers a LIST, not an object, and Bitbucket's an envelope
     * around one, so this is deliberately untyped beyond "some array" — the callers know
     * which shape they asked for.
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
    /**
     * Only an explicit true. A provider that omits the field, or answers a string, has
     * not vouched for the address — and inventing a `false` would be just as wrong as
     * inventing a `true`, because false is a claim we would then store.
     *
     * @param  array<mixed>  $profile
     */
    private function verifiedFlag(array $profile, ?string $path): ?bool
    {
        if ($path === null || $path === '') {
            return null;
        }

        return data_get($profile, $path) === true ? true : null;
    }

    /**
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
