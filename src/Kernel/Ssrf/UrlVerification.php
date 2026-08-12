<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Ssrf;

/**
 * Whether an outbound plane's SSRF host verification is switched on.
 *
 * ONE READING OF THE TOGGLE, for the five planes that have one. Each of them used to write
 * `config(...) !== true`, which is fail-OPEN for every value an operator naturally types:
 * `CBOX_ID_WEBHOOKS_VERIFY_URL=1` and `=on` both arrive as strings, neither is `true`, and
 * the guard silently turns OFF — the exact opposite of what was written. The direction of
 * that mistake is what makes it worth a class: a misread toggle here does not degrade a
 * feature, it removes the control that keeps an outbound fetch away from the metadata
 * service.
 *
 * So: verification is ON unless the configured value is explicitly, recognizably false.
 * Anything unparseable is on, because an operator who cannot spell the value they meant
 * has not asked for the guard to come down.
 */
final class UrlVerification
{
    public static function enforced(string $configKey): bool
    {
        return filter_var(config($configKey, true), FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) !== false;
    }
}
