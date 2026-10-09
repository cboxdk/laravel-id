<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms;

/**
 * Writes the text of a one-time-code message in the recipient's language.
 *
 * The code comes FIRST, so it shows in a lock-screen preview and the operating system's
 * one-time-code autofill picks it up. Every built-in template stays inside the GSM-7
 * alphabet and under 160 characters with a 10-digit code and a 20-character app name, so
 * a code is always one segment — a second segment doubles the cost of every send, and a
 * single character outside GSM-7 (a typographic apostrophe) silently does the same by
 * switching the whole message to UCS-2's 70-character segments.
 *
 * A deployment overrides any language under `cbox-id.sms.messages` with the same
 * placeholders: `:code`, `:app`, `:minutes`.
 */
class SmsMessageComposer
{
    /** @var array<string, string> */
    public const TEMPLATES = [
        'en' => ':code is your :app verification code. It expires in :minutes min. Do not share it with anyone.',
        'da' => ':code er din bekræftelseskode til :app. Den udløber om :minutes min. Del den ikke med nogen.',
        'de' => ':code ist Ihr Bestätigungscode für :app. Er läuft in :minutes Min. ab. Geben Sie ihn nicht weiter.',
        'fr' => ':code est votre code de vérification :app. Il expire dans :minutes min. Ne le partagez avec personne.',
        'nb' => ':code er bekreftelseskoden din for :app. Den utløper om :minutes min. Ikke del den med noen.',
        'sv' => ':code är din verifieringskod för :app. Den går ut om :minutes min. Dela den inte med någon.',
    ];

    /**
     * @param  array<string, string>  $overrides  locale => template
     */
    public function __construct(
        private readonly string $appName,
        private readonly array $overrides = [],
    ) {}

    public function compose(string $code, int $minutes, ?string $locale = null): string
    {
        return strtr($this->template($locale), [
            ':code' => $code,
            ':app' => $this->appName,
            ':minutes' => (string) max(1, $minutes),
        ]);
    }

    /**
     * The template for a locale: an override first, then a built-in, by full tag and
     * then by language (`nb_NO` → `nb`; `no` is Norwegian Bokmål too), then English.
     */
    public function template(?string $locale): string
    {
        foreach (self::candidates($locale) as $candidate) {
            if (isset($this->overrides[$candidate]) && $this->overrides[$candidate] !== '') {
                return $this->overrides[$candidate];
            }

            if (isset(self::TEMPLATES[$candidate])) {
                return self::TEMPLATES[$candidate];
            }
        }

        return $this->overrides['en'] ?? self::TEMPLATES['en'];
    }

    /**
     * @return list<string>
     */
    private static function candidates(?string $locale): array
    {
        if ($locale === null || $locale === '') {
            return ['en'];
        }

        $normalised = strtolower(str_replace('-', '_', $locale));
        $language = explode('_', $normalised)[0];

        return array_values(array_unique([$normalised, $language === 'no' ? 'nb' : $language, 'en']));
    }
}
