<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Hashing;

use Cbox\Id\Identity\Contracts\HashVerifier;

/**
 * The deny-by-default composite the platform actually consults. It tries each
 * registered {@see HashVerifier} in order and asks the FIRST one that
 * {@see HashVerifier::supports()} the format to make the decision.
 *
 * The security-critical property: if NO registered verifier supports a hash's
 * format, {@see verify()} returns false. An unknown format is a rejection, never
 * a silent pass — so importing a user with a hash nothing can verify can never
 * become "everyone logs in". The package registers only
 * {@see NativePasswordVerifier} by default; this registry is the single seam a
 * host extends (via `cbox-id.hashing.verifiers`) to teach the platform a foreign
 * format by wrapping a vetted library.
 */
class HashVerifierRegistry implements HashVerifier
{
    /** @var list<HashVerifier> */
    private array $verifiers;

    public function __construct(HashVerifier ...$verifiers)
    {
        $this->verifiers = array_values($verifiers);
    }

    public function supports(string $hash): bool
    {
        return $this->resolve($hash) !== null;
    }

    public function verify(string $password, string $hash): bool
    {
        $verifier = $this->resolve($hash);

        // Deny-by-default: no verifier claims this format → reject.
        return $verifier !== null && $verifier->verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        $verifier = $this->resolve($hash);

        // An unsupported format is definitionally not the current standard; only
        // reached after a successful verify() (which already required support),
        // so in practice a supporting verifier answers here.
        return $verifier === null || $verifier->needsRehash($hash);
    }

    private function resolve(string $hash): ?HashVerifier
    {
        foreach ($this->verifiers as $verifier) {
            if ($verifier->supports($hash)) {
                return $verifier;
            }
        }

        return null;
    }
}
