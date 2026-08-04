<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Identity\Contracts\RelyingParties;
use Cbox\Id\Identity\EnvironmentRelyingParties;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Organization\Models\Environment;
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
class DoctorCommand extends Command
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
        $this->checkPlatformRoot();
        $this->checkIssuer();
        $this->checkAuthorizationEndpoint();
        $this->checkWebAuthn();
        $this->checkProductionHardening();

        // Whatever the HOST added. It knows things this package cannot: which planes its
        // console serves, where its account door lives, whether its own two halves agree.
        foreach (app(HealthChecks::class)->run() as $contributed) {
            $this->results[] = [
                'status' => $contributed->status->value,
                'label' => $contributed->label,
                'detail' => $contributed->detail,
            ];
        }

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

    /**
     * The platform root is where the platform's OWN people are written as subjects, so
     * aiming it at a customer's environment hands that customer's environment admins a
     * way to set an account member's password and sign in as them. The mistake is silent
     * at runtime — everything works, in the wrong tenant — so it is caught here.
     */
    private function checkPlatformRoot(): void
    {
        try {
            $stamped = Environment::query()->where('is_default', true)->first();
        } catch (Throwable) {
            $this->addWarn('Platform root', 'Could not read environments (migrations not run yet?).');

            return;
        }

        if ($stamped !== null) {
            $this->addOk('Platform root', "'{$stamped->slug}' is flagged is_default.");

            return;
        }

        $configured = config('cbox-id.environments.default');

        if (! is_string($configured) || $configured === '') {
            $this->addWarn('Platform root', 'No is_default environment and no CBOX_ID_ENVIRONMENT_DEFAULT — account members have nowhere to live. Run `php artisan cbox-id:install`.');

            return;
        }

        $row = Environment::query()->where('id', $configured)->orWhere('slug', $configured)->first();

        if ($row === null) {
            // Legitimate for a single-tenant self-hosted install: the config key scopes
            // every query and no `environments` row need ever exist. It only matters if
            // this deployment serves ACCOUNTS, which need somewhere to put their people.
            $this->addWarn('Platform root', "CBOX_ID_ENVIRONMENT_DEFAULT is '{$configured}' with no environment row behind it. Fine for a single-tenant install; multi-account deployments need a real environment stamped is_default.");

            return;
        }

        $row->account_id === null
            ? $this->addWarn('Platform root', "Resolved from config to '{$row->slug}'. Stamp it is_default so the answer does not depend on per-process configuration.")
            : $this->addFail('Platform root', "CBOX_ID_ENVIRONMENT_DEFAULT points at '{$row->slug}', which belongs to an account. The platform root must be an environment no customer owns.");
    }

    private function checkIssuer(): void
    {
        $issuer = config('cbox-id.issuer');

        is_string($issuer) && $issuer !== ''
            ? $this->addOk('Issuer', $issuer)
            : $this->addWarn('Issuer', 'CBOX_ID_ISSUER is not set — discovery falls back to the app URL. Set it to your public HTTPS URL.');
    }

    private function checkAuthorizationEndpoint(): void
    {
        $rawPath = config('cbox-id.oauth.authorization_endpoint_path');
        $rawAbsolute = config('cbox-id.oauth.authorization_endpoint');
        $path = is_string($rawPath) ? $rawPath : '';
        $absolute = is_string($rawAbsolute) ? $rawAbsolute : '';
        $configured = $path !== '' || $absolute !== '';

        // OpenID Connect Discovery §3 marks authorization_endpoint REQUIRED, but RFC 8414
        // (plain OAuth) permits omitting it — and a machine-to-machine deployment serving
        // only client_credentials genuinely has no authorization endpoint. So this is a
        // warning, not a failure: it must not fail a valid OAuth-only install, but a host
        // intending to serve OIDC needs to know its discovery document is one certified
        // clients will refuse. The package cannot supply the value itself — it serves the
        // back-channel endpoints, not the consent screen, and advertising a route it does
        // not serve would be worse than omitting it.
        $configured
            ? $this->addOk('Authorization endpoint', $path !== '' ? $path : $absolute)
            : $this->addWarn(
                'Authorization endpoint',
                'Not configured, so discovery omits `authorization_endpoint`. Fine for an OAuth-only '
                .'(client_credentials) deployment; but if you serve OpenID Connect, a conformant client will '
                .'refuse to initialize — set CBOX_ID_AUTHORIZATION_ENDPOINT_PATH to where your app mounts '
                .'/authorize (e.g. /oauth/authorize).',
            );
    }

    /**
     * Unset rp_id/origin is no longer a warning — it is the recommended state, and the
     * Relying Party is derived from the environment's issuer. What is worth reporting is
     * a PIN THAT DOES NOT APPLY here: it looks configured, it is silently overridden on
     * every host but its own, and an operator reading their `.env` would conclude the
     * opposite.
     */
    private function checkWebAuthn(): void
    {
        $parties = $this->laravel->make(RelyingParties::class);

        try {
            $current = $parties->current();
        } catch (Throwable) {
            // Resolving the party reads the environment's issuer, which is a database
            // lookup. Doctor is the tool you run on a box that has not migrated yet, so a
            // missing schema is a state to report, not to die on.
            $this->addWarn('Passkeys (WebAuthn)', 'Cannot resolve the Relying Party until migrations have run.');

            return;
        }

        if (! $parties instanceof EnvironmentRelyingParties) {
            $this->addOk('Passkeys (WebAuthn)', "rp_id {$current->id} (host-bound resolver)");

            return;
        }

        $pinned = $parties->pinned();

        if ($pinned === null) {
            $this->addOk('Passkeys (WebAuthn)', "rp_id {$current->id} (derived from the issuer)");

            return;
        }

        $pinned->origin === $current->origin
            ? $this->addOk('Passkeys (WebAuthn)', "rp_id {$current->id} (pinned)")
            : $this->addWarn(
                'Passkeys (WebAuthn)',
                "CBOX_ID_WEBAUTHN_ORIGIN pins {$pinned->origin}, but this environment has an issuer host "
                ."of its own — ceremonies here run as rp_id {$current->id} instead. Unset both keys unless "
                .'this deployment really does serve passkeys from exactly one origin.',
            );
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
