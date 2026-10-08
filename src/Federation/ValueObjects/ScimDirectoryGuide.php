<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\SpValue;

/**
 * How an identity provider is pointed at our SCIM 2.0 server to push its people to us.
 *
 * Present on a guide only where the IdP can provision a CUSTOM application over SCIM
 * 2.0 — not where it provisions a fixed list of catalogued apps, and not where it is
 * itself a SCIM server. Every one of these carries our base URL and our bearer token,
 * because those are the two things a SCIM push cannot start without.
 */
readonly class ScimDirectoryGuide
{
    /**
     * @param  list<GuideField>  $fields
     * @param  list<string>  $setupSteps  in the IdP's own vocabulary
     */
    public function __construct(
        public array $fields,
        public array $setupSteps,

        /** The vendor's page for it; null when we could not verify one. */
        public ?string $documentationUrl = null,
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
}
