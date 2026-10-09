<?php

declare(strict_types=1);

use Cbox\Id\Otp\Sms\SmsMessageComposer;

/**
 * The GSM 03.38 basic character set (plus the extension table's characters, which cost
 * two septets — none of the templates use them). A single character outside it switches a
 * message to UCS-2 and 70-character segments.
 */
function isGsm7(string $text): bool
{
    $basic = "@£\$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

    foreach (mb_str_split($text) as $char) {
        if (! str_contains($basic, $char)) {
            return false;
        }
    }

    return true;
}

it('writes the code first, in each shipped language', function (string $locale, string $phrase): void {
    $text = (new SmsMessageComposer('Cbox ID'))->compose('123456', 5, $locale);

    expect($text)->toStartWith('123456 ')
        ->and($text)->toContain('Cbox ID')
        ->and(mb_strtolower($text))->toContain('5 min')
        ->and($text)->toContain($phrase);
})->with([
    ['en', 'verification code'],
    ['da', 'bekræftelseskode'],
    ['de', 'Bestätigungscode'],
    ['fr', 'code de vérification'],
    ['nb', 'bekreftelseskoden'],
    ['sv', 'verifieringskod'],
]);

it('keeps every built-in template to one GSM-7 segment at the worst case', function (): void {
    $composer = new SmsMessageComposer(str_repeat('A', 20));

    foreach (array_keys(SmsMessageComposer::TEMPLATES) as $locale) {
        $text = $composer->compose('1234567890', 10, $locale);

        expect(isGsm7($text))->toBeTrue("{$locale} leaves GSM-7")
            ->and(mb_strlen($text))->toBeLessThanOrEqual(160);
    }
});

it('resolves regional tags and Norwegian aliases, and falls back to English', function (): void {
    $composer = new SmsMessageComposer('X');

    expect($composer->template('da-DK'))->toBe(SmsMessageComposer::TEMPLATES['da'])
        ->and($composer->template('nb_NO'))->toBe(SmsMessageComposer::TEMPLATES['nb'])
        ->and($composer->template('no'))->toBe(SmsMessageComposer::TEMPLATES['nb'])
        ->and($composer->template('pt-BR'))->toBe(SmsMessageComposer::TEMPLATES['en'])
        ->and($composer->template(null))->toBe(SmsMessageComposer::TEMPLATES['en']);
});

it('lets a deployment override a language', function (): void {
    $composer = new SmsMessageComposer('Acme', ['da' => 'Kode :code til :app (:minutes min)']);

    expect($composer->compose('654321', 3, 'da'))->toBe('Kode 654321 til Acme (3 min)')
        ->and($composer->compose('654321', 3, 'sv'))->toStartWith('654321 är');
});

it('reads overrides from config', function (): void {
    config()->set('cbox-id.sms.messages', ['en-GB' => 'Code :code', 'xx' => '']);
    config()->set('cbox-id.sms.app_name', 'Acme');

    $composer = app(SmsMessageComposer::class);

    expect($composer->compose('111222', 5, 'en_GB'))->toBe('Code 111222')
        ->and($composer->compose('111222', 5, 'xx'))->toContain('Acme verification code');
});
