<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\ValueObjects;

use Cbox\Id\Directory\Enums\DirectoryProvider;

/**
 * How to connect one HR system: what to create on their side, what to paste on ours, and
 * where their own documentation is.
 *
 * The HR-system counterpart of the identity providers' directory setup in the federation
 * catalogue, kept in the Directory module on purpose: an HR system is never a sign-in
 * provider, so nothing about it belongs in a catalogue whose entries can become buttons on
 * a sign-in page.
 */
readonly class HrisSetup
{
    /**
     * @param  list<HrisCredential>  $credentials  every value the connector reads, in its own keys
     * @param  list<string>  $setupSteps  how to obtain them, in the HR system's own vocabulary
     */
    public function __construct(
        public DirectoryProvider $provider,
        public string $name,
        public array $credentials,
        public array $setupSteps,
        public string $documentationUrl,
        /** Whether the connector can ask for "changed since" rather than everyone. */
        public bool $incremental = false,
    ) {}

    /** @return list<string> */
    public function credentialKeys(): array
    {
        return array_map(static fn (HrisCredential $c): string => $c->key, $this->credentials);
    }

    /** @return list<string> */
    public function requiredCredentialKeys(): array
    {
        return array_values(array_map(
            static fn (HrisCredential $c): string => $c->key,
            array_filter($this->credentials, static fn (HrisCredential $c): bool => $c->required),
        ));
    }

    /** @return list<string> */
    public function secretCredentialKeys(): array
    {
        return array_values(array_map(
            static fn (HrisCredential $c): string => $c->key,
            array_filter($this->credentials, static fn (HrisCredential $c): bool => $c->secret),
        ));
    }
}
