<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

/**
 * Where a person's identity lives in an OAuth 2.0 provider's profile response.
 *
 * OIDC standardises this: `sub`, `email`, `email_verified`, `name`. Plain OAuth 2.0
 * standardises nothing, so every provider answers a different shape — GitHub returns
 * `id` and `login`, Discord returns `id` and `username`, and neither calls the endpoint
 * userinfo. This is the per-provider translation, declared once in the catalogue rather
 * than smeared through the login path as conditionals.
 *
 * `subject` is the load-bearing one. It must be the provider's IMMUTABLE identifier —
 * GitHub's numeric `id`, not `login`; Discord's snowflake `id`, not `username`. Both of
 * those display names can be changed by their owner and then claimed by someone else,
 * so an account linked by display name is an account that can be inherited.
 */
readonly class ProviderProfileMap
{
    public function __construct(
        /** Dot path to the provider's immutable id. */
        public string $subject,

        /** Dot path to the email address, when the profile carries one. */
        public ?string $email = null,

        /** Dot path to a display name. */
        public ?string $name = null,

        /**
         * Dot path to a boolean saying the provider verified the address.
         *
         * Null means the provider does not tell us. That is not the same as false, and
         * the caller must not treat it as verified — an unverified address from a
         * federated provider is exactly how one person signs in as another.
         */
        public ?string $emailVerified = null,

        /**
         * A second endpoint to consult when the profile has no usable email.
         *
         * GitHub is why: `/user` returns `email: null` for anyone who has not made their
         * address public, which is the default. The address is only available from
         * `/user/emails`, with its own scope. Without this, a majority of GitHub sign-ins
         * arrive with no email at all.
         */
        public ?string $emailEndpoint = null,
    ) {}
}
