<?php

declare(strict_types=1);

use Cbox\Id\Otp\Sms\CallingCodes;
use Cbox\Id\Otp\Sms\Exceptions\InvalidPhoneNumber;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;

function parsePhone(string $input, ?string $country = null): string
{
    $number = (new PhoneNumberNormaliser)->parse($input, $country);

    return $number->country.' '.$number->e164();
}

it('reads international formats into E.164 with the country', function (string $input, string $expected): void {
    expect(parsePhone($input))->toBe($expected);
})->with([
    'spaced' => ['+45 12 34 56 78', 'DK +4512345678'],
    'double-zero prefix' => ['0045 12345678', 'DK +4512345678'],
    'bracketed plus' => ['(+45) 12-34-56-78', 'DK +4512345678'],
    'UK bracketed trunk zero' => ['+44 (0)20 7946 0018', 'GB +442079460018'],
    'Sweden mobile' => ['+46 70 123 45 67', 'SE +46701234567'],
    'Norway' => ['+47 412 34 567', 'NO +4741234567'],
    'Finland' => ['+358 40 123 4567', 'FI +358401234567'],
    'Germany' => ['+49 1512 3456789', 'DE +4915123456789'],
    'dots and slashes' => ['+33.6.12/34.56.78', 'FR +33612345678'],
    'United States' => ['+1 (415) 555-2671', 'US +14155552671'],
    'Canada by area code' => ['+1 416 555 0199', 'CA +14165550199'],
    'Jamaica is not the US' => ['+1 876 555 0199', 'JM +18765550199'],
    'Dominican Republic' => ['+1 809 555 0199', 'DO +18095550199'],
    'Kazakhstan inside +7' => ['+7 701 234 5678', 'KZ +77012345678'],
    'Russia' => ['+7 912 345 6789', 'RU +79123456789'],
    'three-digit code' => ['+354 611 1234', 'IS +3546111234'],
]);

it('reads national formats only with a default country, dropping the trunk prefix', function (): void {
    expect(parsePhone('12 34 56 78', 'DK'))->toBe('DK +4512345678')
        ->and(parsePhone('070-123 45 67', 'SE'))->toBe('SE +46701234567')
        ->and(parsePhone('07700 900123', 'gb'))->toBe('GB +447700900123')
        ->and(parsePhone('(415) 555-2671', 'US'))->toBe('US +14155552671')
        ->and(parsePhone('1 415 555 2671', 'US'))->toBe('US +14155552671');
});

it('refuses a national number without a default country', function (): void {
    (new PhoneNumberNormaliser)->parse('12345678');
})->throws(InvalidPhoneNumber::class, 'country code');

it('refuses a national number that lands in another country of a shared plan', function (): void {
    // A Jamaican number typed for the US is refused, not allowed through as American.
    (new PhoneNumberNormaliser)->parse('876 555 0199', 'US');
})->throws(InvalidPhoneNumber::class);

it('refuses what is not a phone number', function (string $input): void {
    expect((new PhoneNumberNormaliser)->isValid($input, 'DK'))->toBeFalse();
})->with([
    'empty' => [''],
    'letters' => ['+45 CALL ME'],
    'extension' => ['+45 12345678 x12'],
    'service code' => ['*#06#'],
    'plus in the middle' => ['45+12345678'],
    'too long input' => [str_repeat('1', 40)],
    'too long for E.164' => ['+45 1234567890123456'],
    'Denmark with seven digits' => ['+45 1234567'],
    'Denmark with nine digits' => ['+45 123456789'],
    'NANP area code starting with 1' => ['+1 155 555 0199'],
    'NANP exchange starting with 0' => ['+1 415 055 0199'],
    'leading zero after the plus' => ['+0 1234 5678'],
    'unassigned code' => ['+28 1234 5678'],
]);

it('refuses every non-geographic range, which is where pumping traffic goes', function (string $input): void {
    expect((new PhoneNumberNormaliser)->isValid($input))->toBeFalse();
})->with([
    'satellite +881' => ['+881 6 1234 5678'],
    'international networks +882' => ['+882 1234 5678'],
    'international networks +883' => ['+883 1234 5678'],
    'premium rate +979' => ['+979 1234 5678'],
    'Inmarsat +870' => ['+870 7712 34567'],
    'freephone +800' => ['+800 1234 5678'],
]);

it('masks all but the calling code and the last two digits', function (): void {
    $number = (new PhoneNumberNormaliser)->parse('+45 12 34 56 78');

    expect($number->masked())->toBe('+45 ******78')
        ->and($number->masked())->not->toContain('1234')
        ->and($number->cacheKey())->toBe(hash('sha256', '+4512345678'))
        ->and($number->equals((new PhoneNumberNormaliser)->parse('0045 1234 5678')))->toBeTrue();
});

it('maps every country it can place back to a calling code', function (): void {
    foreach (CallingCodes::countries() as $country) {
        expect(CallingCodes::forCountry($country))->not->toBeNull();
    }

    expect(CallingCodes::forCountry('dk'))->toBe('45')
        ->and(CallingCodes::forCountry('JM'))->toBe('1')
        ->and(CallingCodes::forCountry('KZ'))->toBe('7')
        ->and(CallingCodes::forCountry('ZZ'))->toBeNull();
});

it('keeps the calling-code table prefix-free so a longest match is unambiguous', function (): void {
    $codes = array_map('strval', array_keys(CallingCodes::COUNTRIES));

    foreach ($codes as $a) {
        foreach ($codes as $b) {
            if ($a !== $b) {
                expect(str_starts_with($b, $a))->toBeFalse("{$a} is a prefix of {$b}");
            }
        }
    }
});
