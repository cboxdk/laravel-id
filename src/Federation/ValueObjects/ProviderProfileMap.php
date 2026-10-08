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

        /**
         * Dot path to the list inside the email endpoint's response; null when the
         * response IS the list.
         *
         * GitHub answers a bare JSON array. Bitbucket answers its standard paginated
         * envelope — `{"values": [...], "pagelen": 10, "next": "..."}` — so the
         * addresses sit under `values`. Reading the envelope as the list finds no
         * entries and the sign-in arrives with no address.
         */
        public ?string $emailListPath = null,

        /** The key, on each entry of that list, holding the address. */
        public string $emailEntryAddress = 'email',

        /**
         * The key, on each entry, that marks the person's primary address — `primary`
         * on GitHub, `is_primary` on Bitbucket. Only an explicit true counts.
         */
        public string $emailEntryPrimary = 'primary',

        /**
         * The key, on each entry, saying the provider confirmed the address — or null
         * when the entries are not to be judged by it.
         *
         * When set it is a REQUIREMENT, not a hint: only a primary address carrying an
         * explicit true here is taken at all, and that address is reported verified.
         * Bitbucket lists unconfirmed addresses beside confirmed ones and lets an
         * unconfirmed one be primary. Taking it would let somebody attach an address
         * they have never received mail at to a new account here — not enough to sign
         * in as its owner, because nothing merges by email, but enough to occupy the
         * address so its real owner cannot.
         *
         * Null keeps the earlier behaviour exactly: the primary is taken and nothing is
         * said about it — which is what GitHub has always had.
         */
        public ?string $emailEntryVerified = null,
    ) {}
}
