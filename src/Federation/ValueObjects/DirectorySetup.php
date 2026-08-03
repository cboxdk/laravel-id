<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Directory\Enums\DirectoryProvider;

/**
 * The directory half of a catalogue entry: how to obtain the credentials that let us read
 * a provider's user list, and which stored provider those credentials belong to.
 *
 * This is a SEPARATE guide from the template's own `setupSteps`, and that separation is
 * the whole reason this object exists rather than a boolean. Connecting Google for
 * sign-in means creating an OAuth client and pasting an id and a secret. Connecting the
 * same Google as a directory means creating a SERVICE ACCOUNT, granting it domain-wide
 * delegation for two read-only scopes in a different console, and naming an administrator
 * for it to impersonate. Same company, same catalogue entry, nothing in common
 * operationally — so a single flat list of steps could only ever be right for one of them,
 * and an administrator following the wrong one gets to the end before finding out.
 *
 * `credentials` lists what the CONNECTOR requires, in the connector's own keys. That is
 * checkable — and checked: a key here that the connector does not read, or one it demands
 * and does not find here, is a setup form that collects the wrong fields and fails at the
 * first sync rather than at the form. Optional credentials with a working default
 * (Google's `customer_id`) are deliberately absent; this is the set without which the
 * connection cannot be made at all.
 */
readonly class DirectorySetup
{
    /**
     * @param  list<ProviderParameter>  $credentials  every credential the connector requires, in its own keys
     * @param  list<string>  $setupSteps  how to obtain them, in the provider's own vocabulary
     */
    public function __construct(
        /**
         * The value stored on `directories.provider`.
         *
         * The catalogue owns the metadata; the enum stays the persistence type, because a
         * stored column is a serialization boundary and rows written before this existed
         * must keep resolving. This field is the join between the two.
         */
        public DirectoryProvider $provider,

        public array $credentials,
        public array $setupSteps,

        /**
         * The provider's own documentation. Required, unlike the login half's: a
         * directory connection is set up in a console most administrators have never
         * opened, and "there is a guide" is most of what the catalogue is for.
         */
        public string $documentationUrl,
    ) {}

    /** @return list<string> */
    public function credentialKeys(): array
    {
        return array_map(static fn (ProviderParameter $p): string => $p->key, $this->credentials);
    }
}
