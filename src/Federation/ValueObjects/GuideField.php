<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\SpValue;
use InvalidArgumentException;

/**
 * One line of a setup guide: which of OUR values goes into which of THEIR fields.
 *
 * `theirs` is the label exactly as the identity provider's admin screen prints it —
 * "Reply URL (Assertion Consumer Service URL)", not "ACS URL" — because the person
 * following the guide is looking for that string on a screen we do not control. It is
 * never translated: the screen is in whatever language the IdP renders, and a translated
 * label is one the person will not find.
 *
 * A {@see SpValue::Literal} field carries its value here, because it is the same for
 * every customer (OneLogin's "SAML nameID format" is "Email" for everyone). Every other
 * field's value is the host's, for one connection — see {@see ServiceProviderValues}.
 */
readonly class GuideField
{
    public function __construct(
        public SpValue $ours,

        /** The IdP's own label for the field, verbatim. */
        public string $theirs,

        /** The value, for a {@see SpValue::Literal} field only. */
        public ?string $literal = null,

        /**
         * True when the field may be left empty — our Single Logout URL, say, which an
         * IdP accepts but does not require. A console can fold these away.
         */
        public bool $optional = false,

        /**
         * Where on their screen the field sits — the tab, section or file — when the
         * label alone is ambiguous. PingFederate calls the ACS field "Endpoint URL" and so
         * does its logout field; only the tab tells them apart. Also verbatim.
         */
        public ?string $location = null,
    ) {
        if (trim($theirs) === '') {
            throw new InvalidArgumentException('A guide field must name the identity provider\'s label.');
        }

        // A literal without a value is a line telling the administrator to type nothing;
        // a value on anything else would be silently ignored in favour of the host's.
        if (($ours === SpValue::Literal) !== ($literal !== null && $literal !== '')) {
            throw new InvalidArgumentException("Guide field [{$theirs}]: a literal value is required for, and only for, SpValue::Literal.");
        }
    }

    /** The value to show for this field, for one connection; null when the host has none. */
    public function valueFrom(ServiceProviderValues $values): ?string
    {
        return $this->ours === SpValue::Literal ? $this->literal : $values->for($this->ours);
    }
}
