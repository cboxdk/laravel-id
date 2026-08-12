<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\Identity\Contracts\AdminPasswords;
use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\BreachedPasswordCheck;
use Cbox\Id\Identity\Contracts\EmailVerification;
use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\LoginAttempts;
use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\MfaMandate;
use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\PasswordExpiry;
use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Contracts\PasswordReset;
use Cbox\Id\Identity\Contracts\RelyingParties;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SignedInSubject;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\UserImport;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Hashing\HashVerifierRegistry;
use Cbox\Id\Identity\Hashing\NativePasswordVerifier;
use Cbox\Id\Identity\ValueObjects\PasswordHashTarget;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\ServiceProvider;

class IdentityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Deny-by-default hash verification. The registry ships with only the
        // native verifier (bcrypt/argon2 via PHP's vetted password_verify); a host
        // teaches it a foreign format (Firebase scrypt, PBKDF2, …) by listing its
        // own HashVerifier classes in `cbox-id.hashing.verifiers`. An unknown
        // format is refused, never silently trusted.
        $this->app->singleton(HashVerifier::class, function (Application $app): HashVerifier {
            $target = $this->platformHashTarget();

            $verifiers = [new NativePasswordVerifier($target->algorithm, $target->options)];

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
                // Resolved lazily inside the closure: ExternalActionsServiceProvider
                // registers after this one, so the pipeline binding only exists by the
                // time a session manager is actually asked for.
                $app->make(ActionPipeline::class),
                is_numeric($ttl) ? (int) $ttl : 60 * 24,
                is_numeric($idle) ? (int) $idle : 0,
            );
        });
        // Laravel's guard, which is right for a host that uses it and wrong in silence
        // for one that does not — see SignedInSubject on what that silence cost.
        $this->app->singleton(SignedInSubject::class, GuardSignedInSubject::class);

        $this->app->singleton(TotpAuthenticator::class);
        $this->app->singleton(Mfa::class, MfaService::class);
        $this->app->singleton(MagicLink::class, MagicLinkService::class);
        $this->app->singleton(PasswordReset::class, PasswordResetService::class);
        $this->app->singleton(AdminPasswords::class, AdminPasswordService::class);
        $this->app->singleton(AuthPolicies::class, DatabaseAuthPolicies::class);
        $this->app->singleton(PasswordPolicyGuard::class, PasswordPolicyEnforcer::class);
        $this->app->singleton(PasswordExpiry::class, DatabasePasswordExpiry::class);
        $this->app->singleton(MfaMandate::class, DatabaseMfaMandate::class);
        $this->app->singleton(LoginAttempts::class, DatabaseLoginAttempts::class);
        // Inert by default: a breach lookup is a network call against a service the HOST
        // operates, so the library ships a do-nothing default rather than pretending to
        // protection it never wired up. Hosts bind their own.
        $this->app->singleton(BreachedPasswordCheck::class, NeverBreachedCheck::class);
        $this->app->singleton(EmailVerification::class, EmailVerificationService::class);

        // WHICH Relying Party a ceremony runs under is a per-request question — one
        // deployment-wide pair cannot answer for the account root and a tenant host at
        // the same time. Resolved from the environment's issuer, with a configured pin
        // honoured on the host it names ({@see EnvironmentRelyingParties}).
        $this->app->singleton(RelyingParties::class, EnvironmentRelyingParties::class);

        // Real WebAuthn verifier (OpenSSL signatures + vetted CBOR/COSE decoding),
        // unconditionally: rp_id/origin are no longer read from static config, so there
        // is no "not configured yet" state left to refuse in. A deployment that wants
        // passkeys OFF binds {@see UnavailableWebAuthnVerifier} itself — which is honest,
        // where a silently-inert default was not.
        $this->app->singleton(WebAuthnVerifier::class, fn (Application $app): WebAuthnVerifier => new NativeWebAuthnVerifier(
            $app->make(RelyingParties::class),
            config('cbox-id.webauthn.user_verification', true) !== false,
        ));
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
     */
    private function platformHashTarget(): PasswordHashTarget
    {
        $driver = config('hashing.driver');
        $driver = is_string($driver) && $driver !== '' ? $driver : 'bcrypt';

        $argon = [
            'memory_cost' => $this->intConfig('hashing.argon.memory', 65536),
            'time_cost' => $this->intConfig('hashing.argon.time', 4),
            'threads' => $this->intConfig('hashing.argon.threads', 1),
        ];

        return match ($driver) {
            'argon' => new PasswordHashTarget(PASSWORD_ARGON2I, $argon),
            'argon2id' => new PasswordHashTarget(PASSWORD_ARGON2ID, $argon),
            default => new PasswordHashTarget(PASSWORD_BCRYPT, ['cost' => $this->intConfig('hashing.bcrypt.rounds', 12)]),
        };
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
