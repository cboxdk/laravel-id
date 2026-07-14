<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
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

        // Every domain model (organizations, users, signing keys) is owned by an
        // environment — the hard isolation boundary — and the deny-by-default
        // scope returns nothing until one is in context. A fresh install has
        // none, so mint the first one here and pin it as the default; otherwise
        // the signing-key step below (and the operator's first query) silently
        // hit an empty scope. Skipped if migrations haven't run yet.
        $context = $this->laravel->make(EnvironmentContext::class);
        $environment = $this->hasTable('environments') ? $this->ensureEnvironment($context) : null;

        try {
            $mint = $environment instanceof Environment
                ? fn () => $context->runAs($environment, fn () => $keys->activeSigningKey())
                : fn () => $keys->activeSigningKey();
            spin($mint, 'Minting the first signing key…');
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

    /**
     * Ensure at least one environment exists and a default is configured, then
     * return the one to bootstrap against. The environment is the hard boundary
     * and is itself NOT environment-owned, so it is created/queried with the
     * scope suspended.
     */
    private function ensureEnvironment(EnvironmentContext $context): Environment
    {
        return $context->withoutScope(function (): Environment {
            $existing = Environment::query()->orderBy('created_at')->first();

            if ($existing instanceof Environment) {
                $this->ensureDefaultEnvironment($existing);
                $this->line('  <fg=green>✓</> Using existing environment ['.$existing->slug.'].');

                return $existing;
            }

            $name = text(
                label: 'Name your first environment (its own users, keys and issuer)',
                default: 'Production',
                hint: 'The hard isolation boundary. Most single-tenant installs need just one; add more later.',
            );

            $environment = Environment::query()->create([
                'name' => $name !== '' ? $name : 'Production',
                'slug' => $this->uniqueEnvironmentSlug($name !== '' ? $name : 'Production'),
                'status' => 'active',
                'settings' => [],
            ]);

            $this->ensureDefaultEnvironment($environment);
            $this->line('  <fg=green>✓</> Created environment ['.$environment->slug.'].');

            return $environment;
        });
    }

    /**
     * Mark an environment as the single-tenant default so host-less requests
     * resolve — stored in the database, not .env, so it holds across a
     * horizontally-scaled deployment. Skipped when the operator has pinned one
     * explicitly via config, or when a default already exists.
     */
    private function ensureDefaultEnvironment(Environment $environment): void
    {
        $explicit = config('cbox-id.environments.default');

        if (is_string($explicit) && $explicit !== '') {
            return;
        }

        if (Environment::query()->where('is_default', true)->exists()) {
            return;
        }

        $environment->makeDefault();
        $this->line('  <fg=green>✓</> Marked this environment as the default (stored in the database).');
    }

    private function uniqueEnvironmentSlug(string $name): string
    {
        $base = Str::slug($name);
        $base = $base !== '' ? $base : 'default';
        $slug = $base;
        $suffix = 2;

        while (Environment::query()->where('slug', $slug)->exists()) {
            $slug = $base.'-'.$suffix;
            $suffix++;
        }

        return $slug;
    }

    private function needsMigrations(): bool
    {
        return ! $this->hasTable('signing_keys');
    }

    private function hasTable(string $table): bool
    {
        try {
            return Schema::hasTable($table);
        } catch (Throwable) {
            return false;
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
