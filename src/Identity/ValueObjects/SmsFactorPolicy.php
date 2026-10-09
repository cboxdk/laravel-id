<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\SmsFactorPolicies;

/**
 * Whether an environment accepts text messages as a second factor, and on what terms
 * ({@see SmsFactorPolicies}).
 *
 * OFF BY DEFAULT, and every default leans the same way. SMS is the weakest second factor
 * the platform offers: a code can be taken by SIM swap, by number port-out, by SS7
 * interception, or by a phishing page relaying it in real time. It is still far better
 * than a password alone, which is why it exists — for people who cannot use an
 * authenticator app or a passkey — but an environment has to decide to accept it.
 */
readonly class SmsFactorPolicy
{
    /** @var list<string> */
    public array $allowedCountries;

    /**
     * @param  bool  $enabled  SMS may be enrolled and used as a second factor
     * @param  list<string>  $allowedCountries  ISO 3166-1 alpha-2 countries whose numbers may enrol and be texted.
     *                                          EMPTY ADMITS NONE: turning SMS on is also choosing where to send it,
     *                                          because which countries you text is the toll-fraud exposure
     * @param  bool  $privilegedNeedStrongerFactor  an administrator may only add SMS next to an authenticator app or a
     *                                              passkey, and an administrator holding SMS alone is asked to enrol one
     */
    public function __construct(
        public bool $enabled = false,
        array $allowedCountries = [],
        public bool $privilegedNeedStrongerFactor = true,
    ) {
        $this->allowedCountries = self::normaliseCountries($allowedCountries);
    }

    /** Whether a number in `$country` may enrol and be texted under this policy. */
    public function allowsCountry(string $country): bool
    {
        return $this->enabled && in_array(strtoupper($country), $this->allowedCountries, true);
    }

    /**
     * Upper-case, two-letter, de-duplicated, sorted. Anything that is not two letters is
     * dropped rather than trusted.
     *
     * @param  array<mixed>  $countries
     * @return list<string>
     */
    public static function normaliseCountries(array $countries): array
    {
        $clean = [];

        foreach ($countries as $country) {
            if (is_string($country) && preg_match('/^[A-Za-z]{2}$/', trim($country)) === 1) {
                $clean[] = strtoupper(trim($country));
            }
        }

        $clean = array_values(array_unique($clean));
        sort($clean);

        return $clean;
    }
}
