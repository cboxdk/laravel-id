<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Throwable;

/**
 * `cbox-id:doctor` — a friendly health check. It looks over everything the
 * platform needs to run correctly and tells you, in plain language, what's good,
 * what's a warning, and what's broken (with the exact fix). Run it after install,
 * after a deploy, or any time something feels off. You should not need to be an
 * identity expert to read the output.
 */
final class DoctorCommand extends Command
{
    protected $signature = 'cbox-id:doctor';

    protected $description = 'Check that the Cbox ID platform is configured correctly and ready to run';

    /** @var list<array{status: string, label: string, detail: string}> */
    private array $results = [];

    public function handle(): int
    {
        $this->line('');
        $this->line('  <options=bold>Cbox ID — health check</>');
        $this->line('  <fg=gray>Looking over your setup…</>');
        $this->line('');

        $this->checkExtensions();
        $this->checkCryptoKey();
        $this->checkMigrations();
        $this->checkSigningKeys();
        $this->checkIssuer();
        $this->checkWebAuthn();
        $this->checkProductionHardening();

        foreach ($this->results as $result) {
            $this->line('  '.$this->icon($result['status']).' '.$result['label']);

            if ($result['detail'] !== '') {
                $this->line('     <fg=gray>'.$result['detail'].'</>');
            }
        }

        $fails = count(array_filter($this->results, static fn (array $r): bool => $r['status'] === 'fail'));
        $warns = count(array_filter($this->results, static fn (array $r): bool => $r['status'] === 'warn'));

        $this->line('');

        if ($fails > 0) {
            $this->line("  <fg=red;options=bold>✗ {$fails} problem(s) to fix</> <fg=gray>({$warns} warning(s))</>");
            $this->line('');

            return self::FAILURE;
        }

        if ($warns > 0) {
            $this->line("  <fg=yellow;options=bold>✓ Ready, with {$warns} warning(s) worth a look</>");
            $this->line('');

            return self::SUCCESS;
        }

        $this->line('  <fg=green;options=bold>✓ Everything looks healthy. You are good to go.</>');
        $this->line('');

        return self::SUCCESS;
    }

    private function checkExtensions(): void
    {
        $missing = array_filter(['sodium', 'openssl'], static fn (string $ext): bool => ! extension_loaded($ext));

        $missing === []
            ? $this->addOk('PHP extensions', 'sodium and openssl are loaded.')
            : $this->addFail('PHP extensions', 'Missing: '.implode(', ', $missing).'. Enable them in php.ini — the crypto layer needs them.');
    }

    private function checkCryptoKey(): void
    {
        $key = config('cbox-id.crypto.key');
        $decoded = is_string($key) && $key !== '' ? base64_decode($key, true) : false;

        if ($decoded !== false && strlen($decoded) === 32) {
            $this->addOk('Crypto master key', 'Set and valid (32 bytes). Keep it backed up separately from the database.');

            return;
        }

        $this->addFail('Crypto master key', 'CBOX_ID_CRYPTO_KEY is missing or not a base64 32-byte value. Run `php artisan cbox-id:install` to generate one.');
    }

    private function checkMigrations(): void
    {
        try {
            $present = Schema::hasTable('signing_keys') && Schema::hasTable('oauth_clients') && Schema::hasTable('auth_sessions');
        } catch (Throwable) {
            $this->addFail('Database', 'Could not connect to the database. Check your DB_* settings.');

            return;
        }

        $present
            ? $this->addOk('Migrations', 'Core tables exist.')
            : $this->addFail('Migrations', 'Core tables are missing. Run `php artisan migrate`.');
    }

    private function checkSigningKeys(): void
    {
        try {
            $active = SigningKey::query()->where('status', KeyStatus::Active->value)->count();
        } catch (Throwable) {
            $this->addWarn('Signing keys', 'Could not read signing keys (migrations not run yet?).');

            return;
        }

        $active > 0
            ? $this->addOk('Signing keys', "{$active} active key(s). Tokens can be signed and the JWKS is populated.")
            : $this->addWarn('Signing keys', 'No active signing key yet — one is minted on first use, or run `php artisan cbox-id:install`.');
    }

    private function checkIssuer(): void
    {
        $issuer = config('cbox-id.issuer');

        is_string($issuer) && $issuer !== ''
            ? $this->addOk('Issuer', $issuer)
            : $this->addWarn('Issuer', 'CBOX_ID_ISSUER is not set — discovery falls back to the app URL. Set it to your public HTTPS URL.');
    }

    private function checkWebAuthn(): void
    {
        $rpId = config('cbox-id.webauthn.rp_id');
        $origin = config('cbox-id.webauthn.origin');

        is_string($rpId) && $rpId !== '' && is_string($origin) && $origin !== ''
            ? $this->addOk('Passkeys (WebAuthn)', "rp_id {$rpId}")
            : $this->addWarn('Passkeys (WebAuthn)', 'rp_id/origin not set — passkey sign-in is disabled until configured.');
    }

    private function checkProductionHardening(): void
    {
        if (! $this->laravel->environment('production')) {
            $this->addOk('Environment', 'Non-production — hardening checks are advisory.');

            return;
        }

        $issues = [];

        if (config('app.debug') === true) {
            $issues[] = 'APP_DEBUG is true';
        }

        if (config('session.secure') !== true) {
            $issues[] = 'SESSION_SECURE_COOKIE is not true';
        }

        if (config('session.encrypt') !== true) {
            $issues[] = 'SESSION_ENCRYPT is not true';
        }

        $issues === []
            ? $this->addOk('Production hardening', 'Debug off, secure + encrypted sessions.')
            : $this->addFail('Production hardening', implode('; ', $issues).'. Fix these before serving traffic.');
    }

    private function addOk(string $label, string $detail = ''): void
    {
        $this->results[] = ['status' => 'ok', 'label' => $label, 'detail' => $detail];
    }

    private function addWarn(string $label, string $detail = ''): void
    {
        $this->results[] = ['status' => 'warn', 'label' => $label, 'detail' => $detail];
    }

    private function addFail(string $label, string $detail = ''): void
    {
        $this->results[] = ['status' => 'fail', 'label' => $label, 'detail' => $detail];
    }

    private function icon(string $status): string
    {
        return match ($status) {
            'ok' => '<fg=green>✓</>',
            'warn' => '<fg=yellow>!</>',
            default => '<fg=red>✗</>',
        };
    }
}
