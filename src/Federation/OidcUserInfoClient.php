<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\OidcUserInfo;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Support\OrganizationVouchedEmail;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Illuminate\Support\Facades\Http;

/**
 * Reads the person's address and name from an OpenID Provider's UserInfo endpoint
 * (OpenID Connect Core §5.3), for the catalogue providers that keep them there.
 *
 * Intuit is the case. Its `id_token` carries the subject, the audience, the company
 * (`realmid`) and the times — no address — and its documentation says the address and
 * `emailVerified` come from UserInfo. Without this every Intuit sign-in arrives with no
 * email at all.
 *
 * Three rules, each from the spec or from the failure it prevents:
 *
 *  1. **Only for a provider that declares it.** Every other connection gets its
 *     principal back untouched and no request is made, so nothing about Google, Entra or
 *     a hand-configured IdP changes.
 *  2. **The UserInfo `sub` must equal the token's** (Core §5.3.2: "MUST be verified to
 *     exactly match"). An access token that somehow answered for someone else must not
 *     attach their address to this person.
 *  3. **The token wins.** UserInfo fills only what the signed `id_token` left empty. A
 *     signed claim is a stronger statement than an unsigned response over TLS, and a
 *     provider that puts the address in both must not have the weaker one chosen.
 *
 * A provider's "verified" flag is carried under exactly the rule the `id_token` path
 * applies — {@see OrganizationVouchedEmail} — so UserInfo is not a side door around it.
 */
class OidcUserInfoClient implements OidcUserInfo
{
    public function __construct(
        private readonly Connections $connections,
        private readonly OrganizationVouchedEmail $vouched,
    ) {}

    public function complete(Connection $connection, FederatedPrincipal $principal, ?string $accessToken): FederatedPrincipal
    {
        $template = $this->template($connection);

        if ($template === null) {
            return $principal;
        }

        $config = $this->connections->oidcConfig($connection);
        $endpoint = $config->userinfoEndpoint
            ?? throw InvalidAssertion::make($template->key.' connection has no userinfo_endpoint');

        if ($accessToken === null) {
            throw InvalidAssertion::make('token response contained no access_token for userinfo');
        }

        $claims = $this->fetch($endpoint, $accessToken);
        $map = $template->profile;

        $subject = $claims[$map->subject] ?? null;

        if (! is_string($subject) || ! hash_equals($principal->subject, $subject)) {
            throw InvalidAssertion::make('userinfo subject does not match the id_token');
        }

        $email = $principal->email ?? $this->stringAt($claims, $map->email);

        // Verified-ness travels with the address it describes. When the token supplied
        // the address, the token's verdict stands; UserInfo's flag is only read for an
        // address that came from UserInfo.
        $emailVerified = $principal->email !== null
            ? $principal->emailVerified
            : $this->vouched->verified($connection, $email, $map->emailVerified === null ? null : data_get($claims, $map->emailVerified));

        return new FederatedPrincipal(
            provider: $principal->provider,
            subject: $principal->subject,
            email: $email,
            name: $principal->name ?? $this->stringAt($claims, $map->name),
            connectionId: $principal->connectionId,
            emailVerified: $emailVerified,
            // The token's claims stay the record of what was asserted — the nonce check
            // and the audit trail read them — with UserInfo kept beside them, not merged
            // over them.
            raw: [...$principal->raw, 'userinfo' => $claims],
        );
    }

    /** The catalogue entry when — and only when — it says the identity lives in UserInfo. */
    private function template(Connection $connection): ?ProviderTemplate
    {
        $provider = $connection->provider;
        $template = $provider === null ? null : ProviderCatalog::find($provider);

        return $template !== null && $template->isOidc() && $template->profileFromUserInfo ? $template : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(string $endpoint, string $accessToken): array
    {
        // Discovered from a document an administrator pointed us at, so it goes through
        // the same DNS-pinned gate as the token endpoint and the JWKS.
        try {
            $pinned = SafeFederationUrl::pinnedOptions($endpoint);
        } catch (UnsafeFederationUrl $e) {
            throw InvalidAssertion::make('userinfo endpoint blocked: '.$e->getMessage());
        }

        $response = Http::withOptions($pinned)
            ->withoutRedirecting()
            ->withHeaders([
                'Accept' => 'application/json',
                // Core §5.3.1 / RFC 6750 §2.1: the access token as a Bearer credential.
                'Authorization' => 'Bearer '.$accessToken,
            ])
            ->timeout(10)
            ->get($endpoint);

        if (! $response->successful()) {
            throw InvalidAssertion::make('userinfo request failed');
        }

        // Only a JSON object. A provider answering a signed `application/jwt` UserInfo
        // response would need its own verification step; none in the catalogue does.
        $body = $response->json();

        if (! is_array($body)) {
            throw InvalidAssertion::make('userinfo response was not a JSON object');
        }

        $claims = [];

        foreach ($body as $key => $value) {
            if (is_string($key)) {
                $claims[$key] = $value;
            }
        }

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function stringAt(array $claims, ?string $path): ?string
    {
        if ($path === null || $path === '') {
            return null;
        }

        $value = data_get($claims, $path);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
