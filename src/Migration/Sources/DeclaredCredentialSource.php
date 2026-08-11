<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Sources;

use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Migration\Contracts\LegacyCredentialSource;
use Cbox\Id\Migration\Models\LegacyLoginDeclarationRecord;
use Cbox\Ssrf\Contracts\UrlGuard;
use Illuminate\Http\Client\Factory as Http;

/**
 * The legacy source an app declared in its manifest — once a person has approved it.
 *
 * WHY THIS EXISTS RATHER THAN JUST BINDING `HttpCredentialSource`: binding one means an
 * operator pastes a URL into configuration and a secret into an env file, while the app
 * holds the same two values in its own deploy. Two places, and they drift. The manifest is
 * already how an app declares what it is — its roles, its permissions, versioned with the
 * code that depends on them — and where its old login lives is the same kind of fact.
 *
 * APPROVAL IS THE WHOLE DIFFERENCE FROM EVERYTHING ELSE IN A MANIFEST. A role an app gets
 * wrong harms that app. This puts a URL on the environment's sign-in path, where every
 * unknown email and the password typed with it is offered to it — so a client holding
 * `apps.manifest` that could enable it unilaterally would be a credential harvester with a
 * scope for the purpose. An unapproved declaration answers null to everything, exactly as
 * if no source were bound at all.
 *
 * Resolved per call rather than cached: approval is revoked during incidents, and a source
 * that keeps working for the lifetime of a worker after somebody hits "revoke" is not
 * revoked. The read is one indexed row on a path that is already making a network call.
 */
class DeclaredCredentialSource implements LegacyCredentialSource
{
    public function __construct(
        private readonly Http $http,
        private readonly UrlGuard $ssrf,
        private readonly SecretBox $secrets,
    ) {}

    public function verify(string $email, string $password): ?ImportedUser
    {
        return $this->delegate()?->verify($email, $password);
    }

    public function find(string $email): ?ImportedUser
    {
        return $this->delegate()?->find($email);
    }

    /**
     * The HTTP source behind the approved declaration, or null when there is none.
     *
     * Null covers all three of "nothing declared", "declared but not approved" and "the
     * secret will not open" — because the caller does the same thing with each, and it is
     * the same thing it does when no source is configured: refuse, and let the sign-in
     * fail as an ordinary wrong password.
     */
    private function delegate(): ?HttpCredentialSource
    {
        $record = LegacyLoginDeclarationRecord::query()
            ->whereNotNull('approved_at')
            ->first();

        if (! $record instanceof LegacyLoginDeclarationRecord) {
            return null;
        }

        $secret = $this->secrets->open($record->secret_encrypted, $record->secretContext());

        return new HttpCredentialSource($this->http, $this->ssrf, $record->url, $secret);
    }
}
