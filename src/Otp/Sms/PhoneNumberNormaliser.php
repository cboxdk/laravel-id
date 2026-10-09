<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms;

use Cbox\Id\Otp\Sms\Exceptions\InvalidPhoneNumber;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;

/**
 * Turns what a person typed into an E.164 {@see PhoneNumber} with a country, or refuses.
 *
 * Small on purpose. A full numbering-plan library is a large dependency that changes
 * monthly; what the platform needs from a number is narrower — canonical form, so one
 * phone is one rate-limit key; and a country, so the allow-list can be checked. Range
 * allocation is left to the provider, which rejects unallocated numbers anyway.
 *
 * Accepted: `+45 12 34 56 78`, `0045 12345678`, `+44 (0)20 7946 0018`, `(+45) 12-34-56-78`,
 * and — only when a default country is given — national format (`070-123 45 67` in `SE`).
 * Refused: letters, extensions, anything under a non-geographic calling code, and
 * lengths outside the plan.
 */
class PhoneNumberNormaliser
{
    /** Longer than any honest formatting of a 15-digit number. Bounds the work on junk. */
    private const MAX_INPUT = 32;

    /**
     * @param  string|null  $defaultCountry  ISO 3166-1 alpha-2 used for a number typed without a country code
     *
     * @throws InvalidPhoneNumber
     */
    public function parse(string $input, ?string $defaultCountry = null): PhoneNumber
    {
        $input = trim($input);

        if ($input === '' || strlen($input) > self::MAX_INPUT) {
            throw InvalidPhoneNumber::malformed();
        }

        // Only digits, a leading plus and the usual separators. Anything else — letters,
        // `x123` extensions, `*`/`#` service codes — is not a number to text.
        if (preg_match('/^\(?\+?[0-9\s().\-\/]+$/', $input) !== 1) {
            throw InvalidPhoneNumber::malformed();
        }

        // `+44 (0)20 …`: the bracketed trunk zero is a formatting convention, not a digit.
        $input = (string) preg_replace('/\(\s*0\s*\)/', '', $input);

        $international = str_contains($input, '+');
        $digits = (string) preg_replace('/\D/', '', $input);

        if (! $international && str_starts_with($digits, '00')) {
            $international = true;
            $digits = substr($digits, 2);
        }

        if ($international) {
            return $this->fromInternational($digits);
        }

        if ($defaultCountry === null || $defaultCountry === '') {
            throw InvalidPhoneNumber::needsCountry();
        }

        return $this->fromNational($digits, strtoupper($defaultCountry));
    }

    /**
     * True when `$input` parses. For validation rules that only want a yes or no.
     */
    public function isValid(string $input, ?string $defaultCountry = null): bool
    {
        try {
            $this->parse($input, $defaultCountry);

            return true;
        } catch (InvalidPhoneNumber) {
            return false;
        }
    }

    private function fromInternational(string $digits): PhoneNumber
    {
        if (strlen($digits) < 7 || strlen($digits) > 15) {
            throw InvalidPhoneNumber::wrongLength();
        }

        // No calling code starts with 0. Refused before the table lookup, which keys by
        // integer and would otherwise read `01…` as `1`.
        if (str_starts_with($digits, '0')) {
            throw InvalidPhoneNumber::malformed();
        }

        foreach ([1, 2, 3] as $length) {
            $code = substr($digits, 0, $length);

            if (isset(CallingCodes::COUNTRIES[(int) $code])) {
                return $this->build($code, substr($digits, $length));
            }
        }

        throw InvalidPhoneNumber::unknownCountry();
    }

    private function fromNational(string $digits, string $country): PhoneNumber
    {
        $code = CallingCodes::forCountry($country);

        if ($code === null) {
            throw InvalidPhoneNumber::unknownCountry();
        }

        if ($code === '1' && strlen($digits) === 11 && str_starts_with($digits, '1')) {
            $digits = substr($digits, 1);
        } elseif (in_array($country, CallingCodes::ZERO_TRUNK, true) && str_starts_with($digits, '0')) {
            $digits = substr($digits, 1);
        }

        $number = $this->build($code, $digits);

        // A national number typed for one country must land in it. `+1` is shared, so a
        // Jamaican number typed with a default of US is refused here rather than being
        // quietly allowed through as American.
        if ($number->country !== $country) {
            throw InvalidPhoneNumber::unknownCountry();
        }

        return $number;
    }

    private function build(string $code, string $national): PhoneNumber
    {
        $country = $this->countryFor($code, $national);

        [$min, $max] = CallingCodes::LENGTHS[$country] ?? [4, 14];
        $length = strlen($national);

        if ($length < $min || $length > $max || strlen($code) + $length > 15) {
            throw InvalidPhoneNumber::wrongLength();
        }

        if ($code === '1' && preg_match('/^[2-9]\d{2}[2-9]\d{6}$/', $national) !== 1) {
            throw InvalidPhoneNumber::malformed();
        }

        return new PhoneNumber($code, $national, $country);
    }

    private function countryFor(string $code, string $national): string
    {
        if ($code === '1') {
            return CallingCodes::NANP_AREAS[(int) substr($national, 0, 3)] ?? 'US';
        }

        // Kazakhstan shares +7 with Russia; its numbers begin 6 or 7.
        if ($code === '7' && in_array(substr($national, 0, 1), ['6', '7'], true)) {
            return 'KZ';
        }

        return CallingCodes::COUNTRIES[(int) $code];
    }
}
