<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\EmailVerification;
use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\PasswordReset;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\UserImport;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Hashing\HashVerifierRegistry;
use Cbox\Id\Identity\Hashing\NativePasswordVerifier;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\ServiceProvider;

final class IdentityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Deny-by-default hash verification. The registry ships with only the
        // native verifier (bcrypt/argon2 via PHP's vetted password_verify); a host
        // teaches it a foreign format (Firebase scrypt, PBKDF2, …) by listing its
        // own HashVerifier classes in `cbox-id.hashing.verifiers`. An unknown
        // format is refused, never silently trusted.
        $this->app->singleton(HashVerifier::class, function (Application $app): HashVerifier {
            [$algorithm, $options] = $this->platformHashTarget();

            $verifiers = [new NativePasswordVerifier($algorithm, $options)];

            $configured = config('cbox-id.hashing.verifiers');
            if (is_array($configured)) {
                foreach ($configured as $class) {
                    if (is_string($class) && is_a($class, HashVerifier::class, true)) {
                        $instance = $app->make($class);
                        if ($instance instanceof HashVerifier) {
                            $verifiers[] = $instance;
                        }
                    }
                }
            }

            return new HashVerifierRegistry(...$verifiers);
        });

        // A host app binds its own subject resolver to integrate with an existing
        // user store (or several); otherwise the self-contained default is used.
        $this->app->singleton(Subjects::class, function (Application $app): Subjects {
            $resolver = config('cbox-id.subject.resolver');

            if (is_string($resolver) && is_a($resolver, Subjects::class, true)) {
                $instance = $app->make($resolver);

                if ($instance instanceof Subjects) {
                    return $instance;
                }
            }

            return $app->make(DatabaseSubjects::class);
        });
        $this->app->singleton(SessionManager::class, function (Application $app): SessionManager {
            $ttl = config('cbox-id.sessions.ttl_minutes', 60 * 24);
            $idle = config('cbox-id.sessions.idle_minutes', 0);

            return new DatabaseSessionManager(
                $app->make(EventBus::class),
                $app->make(AuditLog::class),
                is_numeric($ttl) ? (int) $ttl : 60 * 24,
                is_numeric($idle) ? (int) $idle : 0,
            );
        });
        $this->app->singleton(TotpAuthenticator::class);
        $this->app->singleton(Mfa::class, MfaService::class);
        $this->app->singleton(MagicLink::class, MagicLinkService::class);
        $this->app->singleton(PasswordReset::class, PasswordResetService::class);
        $this->app->singleton(EmailVerification::class, EmailVerificationService::class);

        // Real WebAuthn verifier (OpenSSL signatures + vetted CBOR/COSE decoding)
        // once rp_id + origin are configured; otherwise it refuses rather than
        // trusting anything. Passkey orchestration always ships.
        $this->app->singleton(WebAuthnVerifier::class, function (): WebAuthnVerifier {
            $rpId = config('cbox-id.webauthn.rp_id');
            $origin = config('cbox-id.webauthn.origin');

            if (is_string($rpId) && $rpId !== '' && is_string($origin) && $origin !== '') {
                return new NativeWebAuthnVerifier($rpId, $origin, config('cbox-id.webauthn.user_verification', true) !== false);
            }

            return new UnavailableWebAuthnVerifier;
        });
        $this->app->singleton(Passkeys::class, PasskeyService::class);

        // Bulk import + lazy password-hash migration (the enterprise wedge).
        $this->app->singleton(UserImport::class, DatabaseUserImport::class);
    }

    /**
     * The platform hasher's target algorithm + cost options, read from the same
     * `hashing` config the Laravel Hasher itself uses — so the native verifier's
     * `needsRehash` decision (what to upgrade TO) always agrees with what
     * {@see Hasher::make()} produces. Defaults mirror
     * Laravel's own hasher defaults.
     *
     * @return array{0: string, 1: array<string, int>}
     */
    private function platformHashTarget(): array
    {
        $driver = config('hashing.driver');
        $driver = is_string($driver) && $driver !== '' ? $driver : 'bcrypt';

        $argon = [
            'memory_cost' => $this->intConfig('hashing.argon.memory', 65536),
            'time_cost' => $this->intConfig('hashing.argon.time', 4),
            'threads' => $this->intConfig('hashing.argon.threads', 1),
        ];

        return match ($driver) {
            'argon' => [PASSWORD_ARGON2I, $argon],
            'argon2id' => [PASSWORD_ARGON2ID, $argon],
            default => [PASSWORD_BCRYPT, ['cost' => $this->intConfig('hashing.bcrypt.rounds', 12)]],
        };
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
