<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Mfa\TotpAuthenticator;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

final class IdentityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
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
    }
}
