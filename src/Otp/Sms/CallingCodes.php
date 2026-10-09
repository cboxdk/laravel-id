<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms;

/**
 * The ITU-T E.164 country calling codes, mapped to the ISO 3166-1 country each one
 * belongs to — just enough of a numbering plan to put a number in a country, which is
 * what the toll-fraud allow-list is checked against. Not a validator of individual
 * ranges (that is what a full numbering library does, and this package does not carry
 * one): a number in an allowed country can still be unallocated, and the provider
 * rejects those.
 *
 * DELIBERATELY ABSENT: the non-geographic codes — `+800` freephone, `+808`, `+870`
 * Inmarsat, `+878`, `+881` satellite, `+882`/`+883` international networks, `+888`,
 * `+979` premium rate. They have no country to allow, and several of them are exactly
 * where SMS pumping sends traffic. A number under one of them is refused as having no
 * country, before any allow-list is consulted.
 *
 * Shared codes are resolved to the country that owns the bulk of the plan, with the
 * exceptions that matter for an allow-list split out by prefix: North America (`+1`, by
 * area code — a Caribbean number is NOT the United States, and that is where pumping
 * goes), and Kazakhstan inside `+7`.
 */
final class CallingCodes
{
    /**
     * Calling code => ISO 3166-1 alpha-2. Calling codes are prefix-free, so a longest
     * match over 1–3 digits finds at most one entry. (PHP stores the numeric keys as
     * integers; a string lookup converts the same way, and {@see forCountry()} casts back.)
     *
     * @var array<int, string>
     */
    public const COUNTRIES = [
        '1' => 'US', '7' => 'RU',
        '20' => 'EG', '27' => 'ZA', '30' => 'GR', '31' => 'NL', '32' => 'BE', '33' => 'FR', '34' => 'ES',
        '36' => 'HU', '39' => 'IT', '40' => 'RO', '41' => 'CH', '43' => 'AT', '44' => 'GB', '45' => 'DK',
        '46' => 'SE', '47' => 'NO', '48' => 'PL', '49' => 'DE', '51' => 'PE', '52' => 'MX', '53' => 'CU',
        '54' => 'AR', '55' => 'BR', '56' => 'CL', '57' => 'CO', '58' => 'VE', '60' => 'MY', '61' => 'AU',
        '62' => 'ID', '63' => 'PH', '64' => 'NZ', '65' => 'SG', '66' => 'TH', '81' => 'JP', '82' => 'KR',
        '84' => 'VN', '86' => 'CN', '90' => 'TR', '91' => 'IN', '92' => 'PK', '93' => 'AF', '94' => 'LK',
        '95' => 'MM', '98' => 'IR',
        '211' => 'SS', '212' => 'MA', '213' => 'DZ', '216' => 'TN', '218' => 'LY', '220' => 'GM', '221' => 'SN',
        '222' => 'MR', '223' => 'ML', '224' => 'GN', '225' => 'CI', '226' => 'BF', '227' => 'NE', '228' => 'TG',
        '229' => 'BJ', '230' => 'MU', '231' => 'LR', '232' => 'SL', '233' => 'GH', '234' => 'NG', '235' => 'TD',
        '236' => 'CF', '237' => 'CM', '238' => 'CV', '239' => 'ST', '240' => 'GQ', '241' => 'GA', '242' => 'CG',
        '243' => 'CD', '244' => 'AO', '245' => 'GW', '246' => 'IO', '247' => 'AC', '248' => 'SC', '249' => 'SD',
        '250' => 'RW', '251' => 'ET', '252' => 'SO', '253' => 'DJ', '254' => 'KE', '255' => 'TZ', '256' => 'UG',
        '257' => 'BI', '258' => 'MZ', '260' => 'ZM', '261' => 'MG', '262' => 'RE', '263' => 'ZW', '264' => 'NA',
        '265' => 'MW', '266' => 'LS', '267' => 'BW', '268' => 'SZ', '269' => 'KM', '290' => 'SH', '291' => 'ER',
        '297' => 'AW', '298' => 'FO', '299' => 'GL',
        '350' => 'GI', '351' => 'PT', '352' => 'LU', '353' => 'IE', '354' => 'IS', '355' => 'AL', '356' => 'MT',
        '357' => 'CY', '358' => 'FI', '359' => 'BG', '370' => 'LT', '371' => 'LV', '372' => 'EE', '373' => 'MD',
        '374' => 'AM', '375' => 'BY', '376' => 'AD', '377' => 'MC', '378' => 'SM', '380' => 'UA', '381' => 'RS',
        '382' => 'ME', '383' => 'XK', '385' => 'HR', '386' => 'SI', '387' => 'BA', '389' => 'MK', '420' => 'CZ',
        '421' => 'SK', '423' => 'LI',
        '500' => 'FK', '501' => 'BZ', '502' => 'GT', '503' => 'SV', '504' => 'HN', '505' => 'NI', '506' => 'CR',
        '507' => 'PA', '508' => 'PM', '509' => 'HT', '590' => 'GP', '591' => 'BO', '592' => 'GY', '593' => 'EC',
        '594' => 'GF', '595' => 'PY', '596' => 'MQ', '597' => 'SR', '598' => 'UY', '599' => 'CW',
        '670' => 'TL', '672' => 'NF', '673' => 'BN', '674' => 'NR', '675' => 'PG', '676' => 'TO', '677' => 'SB',
        '678' => 'VU', '679' => 'FJ', '680' => 'PW', '681' => 'WF', '682' => 'CK', '683' => 'NU', '685' => 'WS',
        '686' => 'KI', '687' => 'NC', '688' => 'TV', '689' => 'PF', '690' => 'TK', '691' => 'FM', '692' => 'MH',
        '850' => 'KP', '852' => 'HK', '853' => 'MO', '855' => 'KH', '856' => 'LA', '880' => 'BD', '886' => 'TW',
        '960' => 'MV', '961' => 'LB', '962' => 'JO', '963' => 'SY', '964' => 'IQ', '965' => 'KW', '966' => 'SA',
        '967' => 'YE', '968' => 'OM', '970' => 'PS', '971' => 'AE', '972' => 'IL', '973' => 'BH', '974' => 'QA',
        '975' => 'BT', '976' => 'MN', '977' => 'NP', '992' => 'TJ', '993' => 'TM', '994' => 'AZ', '995' => 'GE',
        '996' => 'KG', '998' => 'UZ',
    ];

    /**
     * North American Numbering Plan area codes that are NOT the United States. Everything
     * else under `+1` with a valid NPA is treated as the US.
     *
     * The Caribbean entries are the ones that matter most: "+1" reads as domestic to a
     * US operator, and premium-rate pumping through `+1 876` (Jamaica) or `+1 809`
     * (Dominican Republic) is a well-worn pattern. An allow-list of `US` does NOT admit
     * them.
     *
     * @var array<int, string>
     */
    public const NANP_AREAS = [
        // Canada
        '204' => 'CA', '226' => 'CA', '236' => 'CA', '249' => 'CA', '250' => 'CA', '257' => 'CA', '263' => 'CA',
        '289' => 'CA', '306' => 'CA', '343' => 'CA', '354' => 'CA', '365' => 'CA', '367' => 'CA', '368' => 'CA',
        '382' => 'CA', '387' => 'CA', '403' => 'CA', '416' => 'CA', '418' => 'CA', '428' => 'CA', '431' => 'CA',
        '437' => 'CA', '438' => 'CA', '450' => 'CA', '460' => 'CA', '468' => 'CA', '474' => 'CA', '506' => 'CA',
        '514' => 'CA', '519' => 'CA', '548' => 'CA', '579' => 'CA', '581' => 'CA', '584' => 'CA', '587' => 'CA',
        '600' => 'CA', '604' => 'CA', '613' => 'CA', '639' => 'CA', '647' => 'CA', '672' => 'CA', '683' => 'CA',
        '705' => 'CA', '709' => 'CA', '742' => 'CA', '753' => 'CA', '778' => 'CA', '780' => 'CA', '782' => 'CA',
        '807' => 'CA', '819' => 'CA', '825' => 'CA', '867' => 'CA', '873' => 'CA', '879' => 'CA', '902' => 'CA',
        '905' => 'CA', '942' => 'CA',
        // Caribbean and Atlantic
        '242' => 'BS', '246' => 'BB', '264' => 'AI', '268' => 'AG', '284' => 'VG', '345' => 'KY', '441' => 'BM',
        '473' => 'GD', '649' => 'TC', '658' => 'JM', '876' => 'JM', '664' => 'MS', '721' => 'SX', '758' => 'LC',
        '767' => 'DM', '784' => 'VC', '809' => 'DO', '829' => 'DO', '849' => 'DO', '868' => 'TT', '869' => 'KN',
        // US territories with their own ISO code
        '340' => 'VI', '670' => 'MP', '671' => 'GU', '684' => 'AS', '787' => 'PR', '939' => 'PR',
    ];

    /**
     * Subscriber-number lengths (after the calling code) for the plans where a wrong
     * length is common enough to be worth catching before a provider charges for it.
     * Elsewhere the E.164 bounds apply (4–14 digits, 15 in total).
     *
     * @var array<string, array{int, int}>
     */
    public const LENGTHS = [
        'DK' => [8, 8], 'NO' => [8, 8], 'SE' => [7, 9], 'FI' => [5, 12], 'IS' => [7, 7], 'DE' => [6, 13],
        'GB' => [9, 10], 'IE' => [7, 9], 'FR' => [9, 9], 'NL' => [9, 9], 'BE' => [8, 9], 'ES' => [9, 9],
        'PT' => [9, 9], 'IT' => [6, 11], 'PL' => [9, 9], 'AT' => [4, 13], 'CH' => [9, 9], 'EE' => [7, 8],
        'US' => [10, 10], 'CA' => [10, 10],
    ];

    /**
     * Countries whose NATIONAL format starts with a `0` trunk prefix that is dropped in
     * international format (`070 123 45 67` in Sweden is `+46 70 123 45 67`). Only used
     * when a number is typed without a country code and a default country is supplied.
     * Italy is absent on purpose: its leading zero is part of the number.
     *
     * @var list<string>
     */
    public const ZERO_TRUNK = [
        'SE', 'FI', 'DE', 'GB', 'IE', 'FR', 'NL', 'BE', 'AT', 'CH', 'AU', 'NZ', 'JP', 'KR', 'IN', 'TR',
        'ZA', 'CN', 'SI', 'HR', 'RS', 'BA', 'ME', 'MK', 'AL', 'BG', 'RO', 'UA', 'IL', 'EG', 'NG', 'KE',
    ];

    /** The calling code a country's numbers start with, or null for a country we cannot text. */
    public static function forCountry(string $country): ?string
    {
        $country = strtoupper($country);

        if ($country === 'US' || in_array($country, self::NANP_AREAS, true)) {
            return '1';
        }

        if ($country === 'KZ') {
            return '7';
        }

        $code = array_search($country, self::COUNTRIES, true);

        return $code === false ? null : (string) $code;
    }

    /**
     * Every ISO country this table can place a number in, sorted.
     *
     * @return list<string>
     */
    public static function countries(): array
    {
        $all = array_values(array_unique([...array_values(self::COUNTRIES), ...array_values(self::NANP_AREAS), 'KZ']));
        sort($all);

        return $all;
    }
}
