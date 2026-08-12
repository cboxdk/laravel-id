<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * An identity asserted by an external provider (SSO/social), to be provisioned
 * into a local user + identity link.
 *
 * Note: the platform never merges an incoming identity into a pre-existing
 * account by matching email — that would let a provider hijack another user's
 * account. A first-seen identity whose email already belongs to an account is
 * refused; linking is an explicit, authenticated action (see Subjects::link()).
 */
readonly class FederatedPrincipal
{
    /**
     * @param  array<string, mixed>  $raw
     */
    public function __construct(
        public string $provider,
        public string $subject,
        public ?string $email = null,
        public ?string $name = null,
        public ?string $connectionId = null,

        /**
         * Whether the PROVIDER says it verified this address.
         *
         * Null is not false. Null means the provider did not tell us, and an address a
         * provider will not vouch for must not be treated as proven — that is exactly how
         * one person signs in as another. Only an explicit true carries over.
         *
         * This existed as a dot path on every catalogue entry (`ProviderProfileMap::
         * $emailVerified`) and was read by nothing, so every account created through
         * Google, Entra, Okta or Apple was stored unverified — and our own `/oauth/userinfo`
         * then told every relying party `email_verified: false` about an address the
         * upstream IdP had verified, forever, because a federated user has no local
         * verification flow to complete.
         */
        public ?bool $emailVerified = null,

        public array $raw = [],
    ) {}

    /**
     * The same principal with a name filled in, for a provider that sends one exactly
     * once and outside the assertion.
     *
     * Apple is the case: the name arrives in a `user` form field on the FIRST
     * authorization and never again, in a POST body rather than the id_token. Merging
     * rather than overwriting, because a name we already hold is the better one — it may
     * have been edited since.
     */
    public function withName(?string $name): self
    {
        if ($this->name !== null || $name === null || trim($name) === '') {
            return $this;
        }

        return new self(
            provider: $this->provider,
            subject: $this->subject,
            email: $this->email,
            name: trim($name),
            connectionId: $this->connectionId,
            emailVerified: $this->emailVerified,
            raw: $this->raw,
        );
    }
}
