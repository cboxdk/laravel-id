<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Dpop;

use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Illuminate\Http\Request;

/**
 * Enforces DPoP sender-constraining at the resource surface (RFC 9449 §7).
 *
 * A resource endpoint reads the presented access token with {@see bearer()}
 * (accepting both the `Bearer` and `DPoP` authorization schemes), introspects it,
 * then calls {@see enforce()}. For a sender-constrained token (one carrying
 * `cnf.jkt`), enforce() requires the request to use the `DPoP` scheme and to
 * carry a valid proof whose key thumbprint matches the binding and whose `ath`
 * matches this exact token — so a stolen bearer alone is worthless. For a plain
 * bearer token it is a no-op, preserving ordinary Bearer access.
 */
final class DpopResourceGuard
{
    public function __construct(private readonly DpopProofValidator $proofs) {}

    /**
     * The access token presented in the Authorization header under either the
     * `Bearer` or `DPoP` scheme, or null when none is present.
     */
    public function bearer(Request $request): ?string
    {
        $header = $request->header('Authorization');

        if (is_string($header) && preg_match('/^(?:Bearer|DPoP)\s+(\S+)$/i', trim($header), $matches) === 1) {
            return $matches[1];
        }

        return null;
    }

    /**
     * @throws InvalidDpopProof when a sender-constrained token is presented
     *                          without a valid, matching DPoP proof
     */
    public function enforce(Request $request, string $accessToken, Introspection $introspection): void
    {
        $boundThumbprint = $introspection->confirmationThumbprint();

        if ($boundThumbprint === null) {
            return; // not sender-constrained — ordinary bearer access.
        }

        if (! $this->usesDpopScheme($request)) {
            throw InvalidDpopProof::make('a DPoP-bound token must be presented with the DPoP scheme');
        }

        $proof = $request->header('DPoP');

        if (! is_string($proof) || $proof === '') {
            throw InvalidDpopProof::make('a DPoP proof is required for this token');
        }

        $presented = $this->proofs->verify($proof, $request->getMethod(), $request->url(), $accessToken);

        if (! hash_equals($boundThumbprint, $presented)) {
            throw InvalidDpopProof::make('the DPoP key does not match the token binding');
        }
    }

    private function usesDpopScheme(Request $request): bool
    {
        $header = $request->header('Authorization');

        return is_string($header) && preg_match('/^DPoP\s+/i', trim($header)) === 1;
    }
}
