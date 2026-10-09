<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\ValueObjects;

use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;

/**
 * A phone number that has been through {@see PhoneNumberNormaliser}: E.164, with the
 * country it belongs to.
 *
 * There is deliberately no public constructor path from a raw string — every number
 * that reaches an SMS provider has been validated, assigned a country (which is what the
 * toll-fraud allow-list is checked against), and stripped of formatting. A number the
 * normaliser cannot place in a country is refused there, so `$country` is never null.
 */
readonly class PhoneNumber
{
    /**
     * @param  string  $callingCode  the country calling code, digits only (`45`, `1`)
     * @param  string  $nationalNumber  the subscriber number after the calling code, digits only
     * @param  string  $country  ISO 3166-1 alpha-2, upper case (`DK`, `US`)
     */
    public function __construct(
        public string $callingCode,
        public string $nationalNumber,
        public string $country,
    ) {}

    /** `+4512345678` — the only form handed to a provider or stored. */
    public function e164(): string
    {
        return '+'.$this->callingCode.$this->nationalNumber;
    }

    /**
     * `+45 ******78` — the form for audit rows, logs and screens.
     *
     * The calling code and the last two digits are enough for a person to recognise
     * their own number and for an operator to spot a pumping pattern (a burst of `+881`
     * or a run of sequential numbers), and not enough to text anyone.
     */
    public function masked(): string
    {
        $visible = 2;
        $length = strlen($this->nationalNumber);

        return '+'.$this->callingCode.' '
            .str_repeat('*', max(0, $length - $visible))
            .substr($this->nationalNumber, -min($visible, $length));
    }

    /**
     * An unkeyed hash of the number for rate-limit keys, so no number lands in a cache
     * key. Not a secret and not a lookup index — a phone number's space is small enough
     * that an unkeyed hash is reversible by enumeration, which is fine for a cache key
     * that lives for a day and never fine for anything stored.
     */
    public function cacheKey(): string
    {
        return hash('sha256', $this->e164());
    }

    public function equals(self $other): bool
    {
        return $this->e164() === $other->e164();
    }
}
