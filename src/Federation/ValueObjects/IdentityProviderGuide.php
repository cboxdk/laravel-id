<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\GuideProtocol;
use Cbox\Id\Federation\Enums\SpValue;
use Cbox\Id\Federation\IdentityProviderGuides;

/**
 * How to connect one enterprise identity provider to us: which screen to open, which of
 * our values goes in which of their fields, and what to bring back. See
 * {@see IdentityProviderGuides} for why this is not a provider catalogue entry.
 */
readonly class IdentityProviderGuide
{
    /**
     * @param  list<GuideField>  $fields  in the order the IdP's screen asks for them
     * @param  list<string>  $setupSteps  English, imperative, in the IdP's own vocabulary
     */
    public function __construct(
        public string $key,
        public string $name,
        public GuideProtocol $protocol,
        public array $fields,
        public GuideReturns $returns,
        public array $setupSteps,

        /** The vendor's own setup page; null when none could be verified. */
        public ?string $documentationUrl = null,

        /** Present only when the IdP can push to a custom app over SCIM 2.0. */
        public ?ScimDirectoryGuide $directory = null,
    ) {}

    /** Whether this guide asks for the given value of ours. */
    public function asksFor(SpValue $value): bool
    {
        foreach ($this->fields as $field) {
            if ($field->ours === $value) {
                return true;
            }
        }

        return false;
    }

    /**
     * The fields an administrator must fill in, leaving out the optional ones.
     *
     * @return list<GuideField>
     */
    public function requiredFields(): array
    {
        return array_values(array_filter($this->fields, static fn (GuideField $field): bool => ! $field->optional));
    }
}
