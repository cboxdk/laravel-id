<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\FederationProtocol;

/**
 * One entry in the provider catalogue: everything about a provider that is the same for
 * every customer, so the only things an administrator supplies are the ones that are not.
 *
 * Before this, connecting Google meant knowing that its issuer is
 * `https://accounts.google.com`, that Entra's names the directory, and that GitHub is
 * not an OpenID Provider at all. The catalogue is where that knowledge lives once
 * instead of in every customer's head.
 *
 * A template is DATA. Adding a provider is a new entry, not a new code path — which is
 * the property that decides whether the fifteenth provider costs the same as the third.
 */
readonly class ProviderTemplate
{
    /**
     * @param  list<string>  $scopes  requested at authorization; must include what the profile map reads
     * @param  list<ProviderParameter>  $parameters  values the administrator supplies before the issuer resolves
     * @param  list<string>  $setupSteps  how to obtain a client id and secret, in the provider's own vocabulary
     */
    public function __construct(
        public string $key,
        public string $name,
        public FederationProtocol $protocol,
        public array $scopes,
        public ProviderProfileMap $profile,

        /**
         * The OIDC issuer, with `{parameter}` placeholders for anything per-installation.
         * Null for OAuth 2.0 providers, which have no issuer and no discovery.
         */
        public ?string $issuerTemplate = null,

        /** OAuth 2.0 only: fixed endpoints, because there is nothing to discover. */
        public ?string $authorizationEndpoint = null,
        public ?string $tokenEndpoint = null,
        public ?string $profileEndpoint = null,

        public array $parameters = [],
        public array $setupSteps = [],

        /** The provider's own documentation for creating the credential. */
        public ?string $documentationUrl = null,

        /**
         * The redirect URI the administrator must register with the provider.
         *
         * Not stored — computed by the host from its own issuer — but named here so the
         * setup screen can show it, because "the redirect URI does not match" is the
         * single most common failure when connecting any of these.
         */
        public bool $requiresRedirectUri = true,
    ) {}

    /**
     * The issuer for this installation, or null when a required parameter is missing.
     *
     * Returns null rather than a half-substituted URL: a template with `{directory}`
     * still in it would be accepted by a URL validator and then fail at discovery with
     * an error naming a host that does not exist.
     *
     * @param  array<string, string>  $values
     */
    public function issuerFor(array $values): ?string
    {
        if ($this->issuerTemplate === null) {
            return null;
        }

        $issuer = $this->issuerTemplate;

        foreach ($this->parameters as $parameter) {
            $value = trim($values[$parameter->key] ?? '');

            if ($value === '') {
                return null;
            }

            $issuer = str_replace('{'.$parameter->key.'}', rawurlencode($value), $issuer);
        }

        return str_contains($issuer, '{') ? null : $issuer;
    }

    public function isOidc(): bool
    {
        return $this->protocol === FederationProtocol::Oidc;
    }
}
