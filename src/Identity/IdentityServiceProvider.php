<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Mfa\TotpAuthenticator;
use Illuminate\Support\ServiceProvider;

final class IdentityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(UserDirectory::class, DatabaseUserDirectory::class);
        $this->app->singleton(SessionManager::class, DatabaseSessionManager::class);
        $this->app->singleton(TotpAuthenticator::class);
        $this->app->singleton(Mfa::class, MfaService::class);
        $this->app->singleton(MagicLink::class, MagicLinkService::class);

        // Passkey orchestration ships; the crypto verifier must be bound to one
        // wrapping a vetted WebAuthn library.
        $this->app->singleton(WebAuthnVerifier::class, UnavailableWebAuthnVerifier::class);
        $this->app->singleton(Passkeys::class, PasskeyService::class);
    }
}
