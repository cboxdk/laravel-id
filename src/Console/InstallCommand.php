<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Throwable;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\intro;
use function Laravel\Prompts\note;
use function Laravel\Prompts\outro;
use function Laravel\Prompts\spin;
use function Laravel\Prompts\text;
use function Laravel\Prompts\warning;

/**
 * `cbox-id:install` — a guided, one-command bootstrap. It generates the crypto
 * master key, asks the few questions that matter (in plain language, with smart
 * defaults), writes them to `.env`, runs the migrations, and mints the first
 * signing key. You should be able to go from a fresh app to a working identity
 * platform without knowing the internals — that's the whole point.
 */
final class InstallCommand extends Command
{
    protected $signature = 'cbox-id:install';

    protected $description = 'Bootstrap the Cbox ID platform — keys, config, migrations, and signing keys';

    public function handle(): int
    {
        intro('Welcome to Cbox ID — let\'s get you set up.');

        // Resolve the key manager only AFTER the crypto key is in place — it
        // depends on the SecretBox, which needs the master key to boot.
        $this->ensureCryptoKey();
        $keys = $this->laravel->make(KeyManager::class);

        $appUrl = is_string($base = config('app.url')) && $base !== '' ? rtrim($base, '/') : 'http://localhost';
        $host = parse_url($appUrl, PHP_URL_HOST);
        $host = is_string($host) && $host !== '' ? $host : 'localhost';

        $issuer = text(
            label: 'Public URL of this identity platform (the token issuer)',
            default: $appUrl,
            hint: 'Use your real HTTPS URL in production, e.g. https://id.acme.com',
        );

        $rpId = text(
            label: 'Passkey domain (WebAuthn rp_id)',
            default: $host,
            hint: 'Usually just your bare domain, e.g. id.acme.com. Leave as-is if unsure.',
        );

        $origin = text(
            label: 'Passkey origin (WebAuthn origin)',
            default: $appUrl,
            hint: 'The full origin passkeys are used from, e.g. https://id.acme.com',
        );

        $this->setEnv('CBOX_ID_ISSUER', $issuer);
        $this->setEnv('CBOX_ID_WEBAUTHN_RP_ID', $rpId);
        $this->setEnv('CBOX_ID_WEBAUTHN_ORIGIN', $origin);
        config([
            'cbox-id.issuer' => $issuer,
            'cbox-id.webauthn.rp_id' => $rpId,
            'cbox-id.webauthn.origin' => $origin,
        ]);

        if ($this->needsMigrations() && confirm('Run database migrations now?', default: true)) {
            spin(fn () => $this->callSilent('migrate', ['--force' => true]), 'Running migrations…');
            $this->line('  <fg=green>✓</> Migrations applied.');
        }

        try {
            spin(fn () => $keys->activeSigningKey(), 'Minting the first signing key…');
            $this->line('  <fg=green>✓</> Signing key ready — the JWKS is populated.');
        } catch (Throwable $e) {
            warning('Could not mint a signing key yet: '.$e->getMessage().' — it will be created on first use.');
        }

        note(
            "You're set up. Next:\n".
            "  • Run  php artisan cbox-id:doctor  to confirm everything is healthy.\n".
            '  • Back up CBOX_ID_CRYPTO_KEY somewhere safe, separate from the database — losing it makes sealed secrets unrecoverable.',
            'Done',
        );

        outro('Cbox ID is ready. 🎉');

        return self::SUCCESS;
    }

    private function ensureCryptoKey(): void
    {
        $existing = config('cbox-id.crypto.key');

        if (is_string($existing) && $existing !== '' && base64_decode($existing, true) !== false) {
            $this->line('  <fg=green>✓</> Crypto master key already set — keeping it.');

            return;
        }

        $key = base64_encode(random_bytes(32));
        $this->setEnv('CBOX_ID_CRYPTO_KEY', $key);
        config(['cbox-id.crypto.key' => $key]);
        $this->laravel->forgetInstance(SecretBox::class);

        $this->line('  <fg=green>✓</> Generated a crypto master key (32 bytes) and wrote it to .env.');
    }

    private function needsMigrations(): bool
    {
        try {
            return ! Schema::hasTable('signing_keys');
        } catch (Throwable) {
            return true;
        }
    }

    private function setEnv(string $key, string $value): void
    {
        $path = $this->laravel->environmentFilePath();

        if (! is_file($path)) {
            file_put_contents($path, '');
        }

        $contents = (string) file_get_contents($path);
        $line = $key.'='.$this->escape($value);

        $contents = preg_match('/^'.preg_quote($key, '/').'=.*$/m', $contents) === 1
            ? (string) preg_replace('/^'.preg_quote($key, '/').'=.*$/m', $line, $contents)
            : rtrim($contents, "\n")."\n".$line."\n";

        file_put_contents($path, $contents);
    }

    private function escape(string $value): string
    {
        // Quote when the value contains characters that would break a bare .env line.
        return preg_match('/\s|#|"|\'/', $value) === 1 ? '"'.str_replace('"', '\"', $value).'"' : $value;
    }
}
