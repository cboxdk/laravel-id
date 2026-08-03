<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\ClientSecretKind;
use Cbox\Id\Federation\Enums\FederationProtocol;
use Cbox\Id\Federation\Enums\ProviderCapability;

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

        /**
         * What this provider means by "client secret" — see {@see ClientSecretKind}.
         *
         * Apple has none to paste: the secret is an ES256 JWT minted from a downloaded
         * signing key, valid at most six months. Treating that as a text field is what
         * makes an Apple integration fail half a year later on a day nobody touched it.
         */
        public ClientSecretKind $secretKind = ClientSecretKind::Value,

        /**
         * The OAuth `response_mode` this provider requires, when it is not the default.
         *
         * Apple POSTs the callback rather than redirecting with a query string as soon as
         * any scope beyond `openid` is requested — so a handler written for a GET simply
         * never runs, and the failure looks like the user cancelled.
         */
        public ?string $responseMode = null,

        /**
         * True when the provider sends the person's name ONCE, on first authorization,
         * and never again.
         *
         * Apple does this. A flow that discards the first response because it was busy
         * creating the account has thrown away the only copy of the name that will ever
         * exist for that user.
         */
        public bool $profileOnFirstAuthorizationOnly = false,

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

        /**
         * How this provider's user list is read, when it can be read at all.
         *
         * Null for the entries that are only ever a sign-in button. Present for the two
         * that are also directories — and its presence IS the directory capability, so
         * the two cannot disagree.
         */
        public ?DirectorySetup $directory = null,
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

    /**
     * What this provider can be used for.
     *
     * DERIVED, never declared. A hand-written capability list is a claim standing beside
     * the data instead of describing it, and the two drift the first time somebody adds
     * an entry: a template claiming `directory` with no {@see DirectorySetup} puts a
     * provider in the console's list that the console cannot then show a single field
     * for. Reading the capabilities off the contents makes that state unrepresentable
     * rather than merely tested for.
     */
    public function capabilities(): ProviderCapabilities
    {
        $capabilities = [];

        if ($this->supportsLogin()) {
            $capabilities[] = ProviderCapability::Login;
        }

        if ($this->directory !== null) {
            $capabilities[] = ProviderCapability::Directory;
        }

        return new ProviderCapabilities(...$capabilities);
    }

    public function supports(ProviderCapability $capability): bool
    {
        return $this->capabilities()->has($capability);
    }

    /**
     * Whether there is enough here to send somebody to this provider and get an identity
     * back: a discoverable issuer for OIDC, or both fixed endpoints for OAuth 2.0.
     *
     * Not `true` for every entry as a matter of course. A directory-only provider is a
     * coherent thing to add later, and it must not appear on the sign-in page just
     * because it appears in the catalogue.
     */
    public function supportsLogin(): bool
    {
        return $this->isOidc()
            ? $this->issuerTemplate !== null
            : $this->authorizationEndpoint !== null && $this->tokenEndpoint !== null;
    }
}
