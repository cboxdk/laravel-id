<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Throwable;

class JwtTokenIntrospector implements TokenIntrospector
{
    public function __construct(private readonly TokenSigner $signer) {}

    public function introspect(string $token): Introspection
    {
        try {
            // Accept every alg the metadata advertises for signing (RS256/ES256/EdDSA),
            // so an EdDSA-signed token isn't silently un-introspectable/un-exchangeable.
            $claims = $this->signer->verify($token, [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::EdDSA]);
        } catch (Throwable) {
            return Introspection::inactive();
        }

        $jti = $claims->string('jti');

        if ($jti === null) {
            return Introspection::inactive();
        }

        $record = AccessToken::query()->where('jti', $jti)->first();

        if ($record === null || $record->revoked_at !== null || $record->expires_at->isPast()) {
            return Introspection::inactive();
        }

        $scope = $claims->string('scope') ?? '';
        $scopes = $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));

        return Introspection::active($claims->subject(), $claims->string('client_id'), $scopes, $claims->all());
    }

    public function revoke(string $jti): void
    {
        AccessToken::query()
            ->where('jti', $jti)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
